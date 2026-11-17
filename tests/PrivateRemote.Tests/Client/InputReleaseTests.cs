using PrivateRemote.Client;
using PrivateRemote.Protocol;

namespace PrivateRemote.Tests.Client;

internal static class InputReleaseTests
{
    public static void FailedReleasesRetryAfterSecureDesktop()
    {
        var blocked = 0;
        var partial = 1;
        var releases = new System.Collections.Concurrent.ConcurrentQueue<RemoteInputEvent>();
        var input = new WindowsInputControl(() => SessionCapability.ScreenControl,
            () => { if (Volatile.Read(ref blocked) != 0) throw new UnauthorizedAccessException(); },
            events =>
            {
                if (events[0] is KeyEvent { IsDown: true } or MouseButtonEvent { IsDown: true }) return (uint)events.Length;
                var count = Interlocked.Exchange(ref partial, 0) != 0 ? 1 : events.Length;
                foreach (var value in events.Take(count)) releases.Enqueue(value);
                return (uint)count;
            });
        input.Send(new KeyEvent(17, true)); input.Send(new MouseButtonEvent(0, true));
        Volatile.Write(ref blocked, 1);
        input.ReleaseAll();
        TestAssert.Equal(0, releases.Count, "Secure desktop must prevent injection without discarding tracked releases.");
        Volatile.Write(ref blocked, 0);
        input.PendingReleases.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
        TestAssert.Equal(2, releases.Count, "Both secure-desktop and partial-send failures must retry until all tracked input is released.");
        TestAssert.True(releases.Contains(new KeyEvent(17, false)) && releases.Contains(new MouseButtonEvent(0, false)), "Only tracked key/button ups may be retried.");
        input.Send(new KeyEvent(17, true));
        input.ReleaseAll();
        TestAssert.Equal(3, releases.Count, "The same input coordinator must accept new-session input after draining predecessor releases.");
    }
}
