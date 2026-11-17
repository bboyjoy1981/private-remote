using System.Buffers.Binary;
using System.Text.Json;
using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public static class DesktopWire
{
    public const int MaximumFrameBytes = 8 * 1024 * 1024;
    private const int ChunkBytes = 60 * 1024;
    public static byte Type(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 5 || !packet[..4].SequenceEqual("PRD1"u8)) throw new InvalidDataException("Unknown desktop packet.");
        if (packet[4] is < 1 or > 7) throw new InvalidDataException("Unknown desktop message type.");
        return packet[4];
    }

    public static byte[] Command(byte type)
    {
        if (type is < 3 or > 5) throw new ArgumentOutOfRangeException(nameof(type));
        var bytes = new byte[5]; "PRD1"u8.CopyTo(bytes); bytes[4] = type; return bytes;
    }
    public static byte[] QualityCommand(byte profile)
    {
        if (profile > 2) throw new ArgumentOutOfRangeException(nameof(profile));
        return [80, 82, 68, 49, 6, profile];
    }
    public static byte[] InputResult(RemoteInputResult result)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(result);
        var packet = new byte[json.Length + 5]; "PRD1"u8.CopyTo(packet); packet[4] = 7; json.CopyTo(packet, 5); return packet;
    }
    public static RemoteInputResult DecodeInputResult(byte[] packet)
    {
        if (Type(packet) != 7 || packet.Length > 4096) throw new InvalidDataException("Invalid input result.");
        var result = JsonSerializer.Deserialize<RemoteInputResult>(packet.AsSpan(5)) ?? throw new InvalidDataException("Empty input result.");
        if (result.Message is null || result.Message.Length > 512) throw new InvalidDataException("Invalid input result text.");
        return result;
    }

    public static IEnumerable<byte[]> EncodeFrame(ulong id, byte[] jpeg)
    {
        if (id == 0 || jpeg.Length is < 1 or > MaximumFrameBytes) throw new ArgumentOutOfRangeException(nameof(jpeg));
        for (var offset = 0; offset < jpeg.Length; offset += ChunkBytes)
        {
            var count = Math.Min(ChunkBytes, jpeg.Length - offset);
            var packet = new byte[21 + count];
            "PRD1"u8.CopyTo(packet); packet[4] = 1;
            BinaryPrimitives.WriteUInt64LittleEndian(packet.AsSpan(5), id);
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(13), jpeg.Length);
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(17), offset);
            jpeg.AsSpan(offset, count).CopyTo(packet.AsSpan(21));
            yield return packet;
        }
    }

    public static byte[] EncodeInput(RemoteInputEvent input)
    {
        WindowsInputControl.ValidateRemoteInput(input, SessionCapability.ScreenControl);
        var data = input switch
        {
            MouseMoveEvent value => new InputPayload("move", value.NormalizedX, value.NormalizedY, 0, false),
            MouseButtonEvent value => new InputPayload("button", 0, 0, value.Button, value.IsDown),
            MouseWheelEvent value => new InputPayload("wheel", 0, 0, value.Delta, false),
            KeyEvent value => new InputPayload("key", 0, 0, value.VirtualKey, value.IsDown),
            TextInputEvent value => new InputPayload(value.Paste ? "paste" : "text", 0, 0, 0, false, value.Text),
            _ => throw new ArgumentOutOfRangeException(nameof(input))
        };
        var json = JsonSerializer.SerializeToUtf8Bytes(data);
        var packet = new byte[5 + json.Length]; "PRD1"u8.CopyTo(packet); packet[4] = 2; json.CopyTo(packet, 5); return packet;
    }

    public static RemoteInputEvent DecodeInput(byte[] packet)
    {
        if (Type(packet) != 2 || packet.Length > 2048) throw new InvalidDataException("Invalid input packet.");
        var data = JsonSerializer.Deserialize<InputPayload>(packet.AsSpan(5)) ?? throw new InvalidDataException("Missing input payload.");
        RemoteInputEvent input = data.Kind switch
        {
            "move" => new MouseMoveEvent(data.X, data.Y),
            "button" => new MouseButtonEvent(data.Code, data.Down),
            "wheel" when data.Code is >= -12000 and <= 12000 => new MouseWheelEvent(data.Code),
            "key" when data.Code is > 0 and < 255 => new KeyEvent((ushort)data.Code, data.Down),
            "text" when data.Text is not null => new TextInputEvent(data.Text),
            "paste" when data.Text is not null => new TextInputEvent(data.Text, true),
            _ => throw new InvalidDataException("Invalid input type or code.")
        };
        WindowsInputControl.ValidateRemoteInput(input, SessionCapability.ScreenControl);
        return input;
    }

    private sealed record InputPayload(string Kind, double X, double Y, int Code, bool Down, string? Text = null);
}

public sealed class DesktopFrameAssembler
{
    private byte[]? _frame;
    private ulong _id, _lastId;
    private int _offset;
    public void Reset() { _frame = null; _offset = 0; }

    public byte[]? Accept(byte[] packet)
    {
        if (DesktopWire.Type(packet) != 1 || packet.Length is <= 21 or > 21 + 60 * 1024) throw new InvalidDataException("Invalid frame chunk.");
        var id = BinaryPrimitives.ReadUInt64LittleEndian(packet.AsSpan(5));
        var length = BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(13));
        var offset = BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(17));
        var count = packet.Length - 21;
        if (id == 0 || length is < 1 or > DesktopWire.MaximumFrameBytes || offset < 0 || offset > length - count)
            throw new InvalidDataException("Invalid frame bounds.");
        if (_frame is null)
        {
            if (offset != 0 || id <= _lastId) throw new InvalidDataException("Missing or replayed frame start.");
            _frame = new byte[length]; _id = id; _offset = 0;
        }
        if (id != _id || length != _frame.Length || offset != _offset) throw new InvalidDataException("Frame chunks arrived out of order.");
        packet.AsSpan(21).CopyTo(_frame.AsSpan(offset)); _offset += count;
        if (_offset != length) return null;
        var result = _frame; _lastId = _id; Reset(); return result;
    }
}
