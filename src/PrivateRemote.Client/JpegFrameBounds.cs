using System.Buffers.Binary;

namespace PrivateRemote.Client;

public static class JpegFrameBounds
{
    public static void Validate(byte[] bytes)
    {
        if (bytes.Length is < 4 or > DesktopWire.MaximumFrameBytes || bytes[0] != 0xff || bytes[1] != 0xd8)
            throw new InvalidDataException("Invalid JPEG frame.");
        var offset = 2;
        while (offset < bytes.Length)
        {
            if (bytes[offset++] != 0xff) throw new InvalidDataException("Invalid JPEG marker.");
            while (offset < bytes.Length && bytes[offset] == 0xff) offset++;
            if (offset >= bytes.Length) break;
            var marker = bytes[offset++];
            if (marker is 0xd9 or 0xda) break;
            if (marker is 0xd8 or >= 0xd0 and <= 0xd7) continue;
            if (offset + 2 > bytes.Length) break;
            var length = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset));
            if (length < 2 || length > bytes.Length - offset) throw new InvalidDataException("Invalid JPEG segment length.");
            if (marker is 0xc0 or 0xc1 or 0xc2)
            {
                if (length < 8) throw new InvalidDataException("Invalid JPEG size header.");
                var height = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset + 3));
                var width = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset + 5));
                if (width is < 1 or > 3840 || height is < 1 or > 2160 || bytes[offset + 7] is < 1 or > 4)
                    throw new InvalidDataException("JPEG dimensions exceed the desktop bounds.");
                return;
            }
            offset += length;
        }
        throw new InvalidDataException("JPEG frame has no supported size header.");
    }
}
