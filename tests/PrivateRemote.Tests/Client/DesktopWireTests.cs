using PrivateRemote.Client;

namespace PrivateRemote.Tests.Client;

internal static class DesktopWireTests
{
    public static void FramesAndInputAreBoundedAndOrdered()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(160000);
        var receiver = new DesktopFrameAssembler();
        byte[]? frame = null;
        foreach (var chunk in DesktopWire.EncodeFrame(1, bytes)) frame = receiver.Accept(chunk);
        TestAssert.SequenceEqual(bytes, frame!, "Chunked frames must reassemble exactly.");
        TestAssert.Throws<InvalidDataException>(() => receiver.Accept(DesktopWire.EncodeFrame(1, bytes).First()), "Frame IDs cannot replay.");
        var input = new MouseMoveEvent(0.25, 0.75);
        TestAssert.Equal(input, DesktopWire.DecodeInput(DesktopWire.EncodeInput(input)), "Mouse coordinates must round trip.");
        TestAssert.Throws<ArgumentOutOfRangeException>(() => DesktopWire.EncodeInput(new MouseMoveEvent(double.NaN, 0)), "Nonfinite positions must be rejected.");
        TestAssert.Throws<InvalidDataException>(() => new DesktopFrameAssembler().Accept(DesktopWire.EncodeFrame(2, bytes).Skip(1).First()), "Missing first chunks must be rejected.");
        TestAssert.Throws<ArgumentOutOfRangeException>(() => DesktopWire.EncodeFrame(3, new byte[DesktopWire.MaximumFrameBytes + 1]).ToArray(), "Frame memory must be bounded.");
        byte[] jpegHeader = [0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 3, 132, 6, 64, 1, 1, 0x11, 0];
        JpegFrameBounds.Validate(jpegHeader);
        jpegHeader[9] = 0x7f;
        TestAssert.Throws<InvalidDataException>(() => JpegFrameBounds.Validate(jpegHeader), "Decoder must reject oversized JPEG dimensions before allocating pixels.");
    }
}
