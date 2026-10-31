using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace WinGuardian.Core.Monitoring;

public enum SignatureStatus
{
    /// <summary>Signed, the signature checks out, and the certificate chains to a trusted root.</summary>
    Valid,
    Unsigned,
    /// <summary>The file carries a signature but its content no longer matches it: modified after signing.</summary>
    Tampered,
    /// <summary>Signed, but the certificate is not trusted (untrusted root, revoked, explicitly distrusted...).</summary>
    Untrusted,
    Error,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Signer, bool FromCatalog, string? Detail)
{
    private static readonly HashSet<string> MicrosoftSigners = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation",
    };

    public bool IsValid => Status == SignatureStatus.Valid;

    /// <summary>
    /// Signed by Microsoft itself. Deliberately excludes "Microsoft Windows Hardware Compatibility
    /// Publisher", which is Microsoft's WHQL signature on third-party drivers.
    /// </summary>
    public bool IsMicrosoft => IsValid && Signer is not null && MicrosoftSigners.Contains(Signer);

    public string Describe() => Status switch
    {
        SignatureStatus.Valid => $"Signed by {Signer}{(FromCatalog ? " (catalog)" : "")}",
        SignatureStatus.Unsigned => "Unsigned",
        SignatureStatus.Tampered => "SIGNATURE BROKEN: the file was modified after it was signed",
        SignatureStatus.Untrusted => $"Signature not trusted ({Detail})",
        _ => $"Signature check failed ({Detail})",
    };
}

/// <summary>
/// Authenticode verification through WinVerifyTrust. Checks the embedded signature first and, if there is
/// none, the system's security catalogs. Catalogs matter: most files that ship with Windows carry no
/// embedded signature and are signed only via a catalog. Revocation checks are disabled (no network).
/// </summary>
public static class SignatureVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int CryptEFileError = unchecked((int)0x80092003);

    private static readonly ConcurrentDictionary<(string, long, long), SignatureInfo> Cache = new();

    /// <summary>Verifies a file's signature; results are cached by path, size and timestamp.</summary>
    public static SignatureInfo Verify(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return new SignatureInfo(SignatureStatus.Error, null, false, "file not found");
            var key = (path.ToUpperInvariant(), info.Length, info.LastWriteTimeUtc.Ticks);
            if (Cache.TryGetValue(key, out var cached)) return cached;

            var result = VerifyUncached(path);
            if (Cache.Count > 20_000) Cache.Clear();
            Cache[key] = result;
            return result;
        }
        catch (Exception ex)
        {
            return new SignatureInfo(SignatureStatus.Error, null, false, ex.Message);
        }
    }

    private static SignatureInfo VerifyUncached(string path)
    {
        var embedded = VerifyEmbedded(path);
        if (embedded.Status != SignatureStatus.Unsigned) return embedded;
        return VerifyCatalog(path) ?? embedded;
    }

    private static SignatureInfo VerifyEmbedded(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = pathPtr,
        };
        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, infoPtr, false);
            return Evaluate(infoPtr, WtdChoiceFile, fromCatalog: false);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    /// <summary>Looks the file's hash up in the installed catalogs; null if no catalog lists it.</summary>
    private static SignatureInfo? VerifyCatalog(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var handle = stream.SafeFileHandle.DangerousGetHandle();

        // Modern catalogs use SHA-256 hashes; older ones SHA-1 (null algorithm).
        foreach (var algorithm in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
            try
            {
                uint hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref hashSize, null, 0);
                if (hashSize == 0) continue;
                var hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref hashSize, hash, 0)) continue;

                var catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero) continue;
                try
                {
                    var catalog = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref catalog, 0)) continue;
                    return VerifyAgainstCatalog(path, handle, catalog.wszCatalogFile, hash, catAdmin);
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(catAdmin, 0);
            }
        }
        return null;
    }

    private static SignatureInfo VerifyAgainstCatalog(string path, IntPtr fileHandle, string catalogPath, byte[] hash, IntPtr catAdmin)
    {
        var catalogPtr = Marshal.StringToHGlobalUni(catalogPath);
        var tagPtr = Marshal.StringToHGlobalUni(Convert.ToHexString(hash));
        var memberPtr = Marshal.StringToHGlobalUni(path);
        var hashPtr = Marshal.AllocHGlobal(hash.Length);
        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        try
        {
            Marshal.Copy(hash, 0, hashPtr, hash.Length);
            Marshal.StructureToPtr(new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                pcwszCatalogFilePath = catalogPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = memberPtr,
                hMemberFile = fileHandle,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = catAdmin,
            }, infoPtr, false);
            return Evaluate(infoPtr, WtdChoiceCatalog, fromCatalog: true);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(hashPtr);
            Marshal.FreeHGlobal(memberPtr);
            Marshal.FreeHGlobal(tagPtr);
            Marshal.FreeHGlobal(catalogPtr);
        }
    }

    private static SignatureInfo Evaluate(IntPtr unionInfo, uint unionChoice, bool fromCatalog)
    {
        var data = new WinTrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice = WtdUiNone,
            dwUnionChoice = unionChoice,
            pInfo = unionInfo,
            dwStateAction = WtdStateActionVerify,
            dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
        };
        var action = GenericVerifyV2;
        var hr = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        try
        {
            return hr switch
            {
                0 => new SignatureInfo(SignatureStatus.Valid, GetSigner(data.hWVTStateData), fromCatalog, null),
                TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown or CryptEFileError
                    => new SignatureInfo(SignatureStatus.Unsigned, null, false, null),
                TrustEBadDigest => new SignatureInfo(SignatureStatus.Tampered, null, fromCatalog, $"0x{hr:X8}"),
                _ => new SignatureInfo(SignatureStatus.Untrusted, GetSigner(data.hWVTStateData), fromCatalog,
                    Marshal.GetExceptionForHR(hr)?.Message.TrimEnd('.', '\r', '\n') ?? $"0x{hr:X8}"),
            };
        }
        finally
        {
            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
    }

    /// <summary>Reads the leaf signing certificate's name from WinVerifyTrust's state data.</summary>
    private static string? GetSigner(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero) return null;
        try
        {
            var provData = WTHelperProvDataFromStateData(stateData);
            if (provData == IntPtr.Zero) return null;
            var signer = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
            if (signer == IntPtr.Zero) return null;
            var provCert = WTHelperGetProvCertFromChain(signer, 0);
            if (provCert == IntPtr.Zero) return null;

            // CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... } - pCert follows the (padded) DWORD.
            var certContext = Marshal.ReadIntPtr(provCert, IntPtr.Size);
            if (certContext == IntPtr.Zero) return null;
            using var cert = new X509Certificate2(certContext);
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch
        {
            return null;
        }
    }

    // ------------------------------------------------------------------ interop

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll")]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint signerIndex, bool counterSigner, uint counterSignerIndex);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certIndex);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string? hashAlgorithm,
        IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, IntPtr file, ref uint hashSize,
        byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags,
        IntPtr previousCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CatalogInfo info, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);
}
