using PrivateRemote.Tests.Protocol;
using PrivateRemote.Tests.Agent;
using PrivateRemote.Tests.Transport;
using PrivateRemote.Tests.Relay;
using PrivateRemote.Tests.Client;
using System.ComponentModel;

var tests = new (string Name, Action Run)[]
{
    ("offline pairing files require local approvals and reject tamper replay expiry", PairingExchangeTests.OfflinePairingRequiresApprovalAndRejectsTamperReplay),
    ("input cleanup retries secure-desktop and partial release failures", InputReleaseTests.FailedReleasesRetryAfterSecureDesktop),
    ("desktop frame chunks and input reject replay and invalid bounds", DesktopWireTests.FramesAndInputAreBoundedAndOrdered),
    ("network hosts establish native channels and reconnect after signed disconnect", NativeHostIntegrationTests.NetworkHostsConnectDisconnectAndReconnect),
    ("device identities sign and verify with the matching key", IdentityTests.SignaturesAreBoundToTheDeviceKey),
    ("protected identity keys survive a same-user reload", IdentityTests.ProtectedKeyRoundTrips),
    ("pairing invitations are single use and reject incorrect tokens", PairingTests.InvitationsAreSingleUse),
    ("expired invitations cannot be consumed", PairingTests.ExpiredInvitationsAreRejected),
    ("revoked devices lose their grants", PairingTests.RevocationRemovesAuthorization),
    ("unknown devices and unapproved capabilities are rejected", PairingTests.UnknownDevicesAndUnapprovedCapabilitiesAreRejected),
    ("session signatures bind peer identity and capabilities", SessionTests.SignaturesBindTheTranscript),
    ("ephemeral peers derive matching fresh session keys", SessionTests.EphemeralKeysAreFreshAndAgree),
    ("authenticated frames reject replay and reordering", SessionTests.FramesRequireInOrderDelivery),
    ("file transfers reject unsafe names and verify completed files", FileTransferTests.CompletedFilesStayWithinSelectedDirectory),
    ("interrupted file transfers do not produce completed files", FileTransferTests.InterruptedTransfersAreDiscarded),
    ("Windows superscript device names are rejected", FileTransferTests.WindowsSuperscriptDeviceNamesAreRejected),
    ("duplicate and hash-mismatched transfers are discarded", FileTransferTests.DuplicateAndHashMismatchTransfersAreDiscarded),
    ("remote input requires an active screen-control grant", FileTransferTests.InputRequiresScreenControl),
    ("file sending reports progress and supports cancellation", FileTransferTests.SendingReportsProgressAndHonorsCancellation),
    ("file metadata can be prepared before sending content", FileTransferTests.SenderCanPrepareMetadataBeforeStreaming),
    ("file sender rejects content changed after preparation", FileTransferTests.SenderRejectsFileChangedAfterMetadataPreparation),
    ("signaling messages are signed and timestamped", SignalingTests.MessagesBindPayloadAndExpiry),
    ("signaling signatures match the claimed device identity", SignalingTests.SignatureMustMatchClaimedDeviceIdentity),
    ("authenticated inbox requires active pairing and rejects replay", SignalingTests.InboxRequiresActivePairingAndRejectsReplay),
    ("signed SDP and ICE establish a real native data channel", NativeNegotiationTests.SignedNegotiationEstablishesNativeDataChannel),
    ("tampered signed SDP is rejected before native negotiation", NativeNegotiationTests.TamperedNegotiationNeverReachesNativePeer),
    ("native negotiation rejects mismatched capability grants", NativeNegotiationTests.CapabilityMismatchNeverReachesNativePeer),
    ("negotiation binds session identity and DTLS fingerprint", NativeNegotiationTests.SessionAndFingerprintRemainBound),
    ("managed native peers transfer data and close after persistent revocation", NativePeerLifecycleTests.RealManagedPeersTransferDataAndCloseOnRevocation),
    ("control-only native peers reject bulk channel use", NativePeerLifecycleTests.ControlOnlyPeerRejectsBulkChannel),
    ("signaling bearer tokens cannot be sent to remote plaintext WebSockets", SignalingTests.RemoteSignalingRequiresTls),
    ("relay policy rejects unknown revoked and replayed devices", RelaySecurityTests.AccessRequiresActivePairedDevicesAndFreshNonce),
    ("two signaling devices exchange concurrent messages and revocation closes their socket", SignalingIntegrationTests.TwoDevicesExchangeSignedMessagesAndRevocationClosesSocket),
    ("direct peer failure falls back to the encrypted relay route", DirectConnectionTests.DirectFailureFallsBackToRelay),
    ("peer authentication failures never trigger relay downgrade", DirectConnectionTests.AuthenticationFailureDoesNotRetry),
    ("peer timeout falls back unless the caller cancelled", DirectConnectionTests.TimeoutFallsBackAndCallerCancellationStops),
    ("unauthenticated or unencrypted peers are never returned", DirectConnectionTests.UnverifiedPeersAreRejected),
    ("pairing is persisted only after local approval", PairingFlowTests.PairingRequiresLocalApprovalAndPersistsAfterApproval),
    ("expired pairing invitations are not persisted", PairingFlowTests.ExpiredInvitationCannotBePersisted),
    ("invalid peer identities do not consume pairing invitations", PairingFlowTests.InvalidPeerIdentityDoesNotConsumeInvitation),
    ("paired devices can be renamed and revoked", PairingFlowTests.DeviceCanBeRenamedAndRevoked),
    ("stored pairings authorize sessions and revocation stops existing negotiation", PairingFlowTests.StoredPairingsAuthorizeSessionsAndRevocationStopsExistingNegotiation),
};

var failures = 0;
var skipped = 0;
foreach (var (name, run) in tests)
{
    try
    {
        run();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        if (exception is NativeDependencyUnavailableException)
        {
            skipped++;
            Console.WriteLine($"SKIP {name}: {exception.Message}");
            continue;
        }

        if (exception is Win32Exception { NativeErrorCode: 2 } && name == "protected identity keys survive a same-user reload")
        {
            skipped++;
            Console.WriteLine($"SKIP {name}: current-user DPAPI profile is unavailable in this execution environment.");
            continue;
        }

        failures++;
        Console.WriteLine($"FAIL {name}: {exception}");
    }
}

Console.WriteLine($"{tests.Length - failures - skipped} passed, {skipped} skipped, {failures} failed (total {tests.Length})");
return failures == 0 ? 0 : 1;
