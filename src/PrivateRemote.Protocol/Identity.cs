using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PrivateRemote.Protocol;

public static class DeviceSecretProtection
{
    public static byte[] Protect(byte[] data) => WindowsCurrentUserDataProtection.Protect(data);
    public static byte[] Unprotect(byte[] data) => WindowsCurrentUserDataProtection.Unprotect(data);
}

public sealed class DeviceIdentity : IDisposable
{
    private readonly ECDsa _signingKey;
    private readonly byte[] _publicKey;
    private readonly object _signingLock = new();
    private bool _disposed;

    private DeviceIdentity(ECDsa signingKey)
    {
        _signingKey = signingKey;
        _publicKey = signingKey.ExportSubjectPublicKeyInfo();
        DeviceId = GetDeviceId(_publicKey);
    }

    public string DeviceId { get; }

    public byte[] PublicKey => _publicKey.ToArray();

    public static DeviceIdentity Create()
    {
        return new DeviceIdentity(ECDsa.Create(ECCurve.NamedCurves.nistP256));
    }

    public byte[] Sign(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        lock (_signingLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _signingKey.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
    }

    public byte[] ExportProtectedPrivateKey()
    {
        lock (_signingLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var privateKey = _signingKey.ExportPkcs8PrivateKey();
            try
            {
                return WindowsCurrentUserDataProtection.Protect(privateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    public static DeviceIdentity FromProtectedPrivateKey(byte[] protectedPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(protectedPrivateKey);
        var privateKey = WindowsCurrentUserDataProtection.Unprotect(protectedPrivateKey);
        try
        {
            var signingKey = ECDsa.Create();
            signingKey.ImportPkcs8PrivateKey(privateKey, out var bytesRead);
            if (bytesRead != privateKey.Length)
            {
                signingKey.Dispose();
                throw new CryptographicException("The protected device key contains trailing data.");
            }

            return new DeviceIdentity(signingKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);

        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length &&
                   verifier.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static string GetDeviceId(byte[] subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
        if (bytesRead != subjectPublicKeyInfo.Length)
        {
            throw new CryptographicException("The public key contains trailing data.");
        }

        return Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)).ToLowerInvariant();
    }

    public void Dispose()
    {
        lock (_signingLock)
        {
            if (_disposed)
            {
                return;
            }

            _signingKey.Dispose();
            _disposed = true;
        }
    }
}

internal static class WindowsCurrentUserDataProtection
{
    private const uint CryptProtectUiForbidden = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", EntryPoint = "CryptProtectData", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", EntryPoint = "CryptUnprotectData", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        out IntPtr description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static byte[] Protect(byte[] plaintext)
    {
        return Transform(plaintext, protect: true);
    }

    public static byte[] Unprotect(byte[] protectedData)
    {
        return Transform(protectedData, protect: false);
    }

    private static byte[] Transform(byte[] input, bool protect)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Device private keys are protected with Windows DPAPI.");
        }

        var inputBlob = Allocate(input);
        DataBlob outputBlob = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            var succeeded = protect
                ? CryptProtectData(ref inputBlob, "PrivateRemote device key", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outputBlob)
                : CryptUnprotectData(ref inputBlob, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outputBlob);
            if (!succeeded)
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Win32Exception(errorCode, $"Windows could not protect or unprotect the device key (Win32 {errorCode}). Ensure the current user's DPAPI profile is loaded.");
            }

            var output = new byte[outputBlob.Size];
            Marshal.Copy(outputBlob.Data, output, 0, output.Length);
            return output;
        }
        finally
        {
            ZeroAndFree(inputBlob);
            if (outputBlob.Data != IntPtr.Zero)
            {
                if (!protect)
                {
                    ZeroMemory(outputBlob.Data, outputBlob.Size);
                }

                LocalFree(outputBlob.Data);
            }

            if (description != IntPtr.Zero)
            {
                LocalFree(description);
            }
        }
    }

    private static DataBlob Allocate(byte[] value)
    {
        var pointer = Marshal.AllocHGlobal(value.Length);
        Marshal.Copy(value, 0, pointer, value.Length);
        return new DataBlob { Size = value.Length, Data = pointer };
    }

    private static void ZeroAndFree(DataBlob blob)
    {
        if (blob.Data == IntPtr.Zero)
        {
            return;
        }

        ZeroMemory(blob.Data, blob.Size);
        Marshal.FreeHGlobal(blob.Data);
    }

    private static void ZeroMemory(IntPtr pointer, int size)
    {
        var zeros = new byte[Math.Min(size, 4096)];
        var offset = 0;
        while (offset < size)
        {
            var count = Math.Min(zeros.Length, size - offset);
            Marshal.Copy(zeros, 0, IntPtr.Add(pointer, offset), count);
            offset += count;
        }
    }
}
