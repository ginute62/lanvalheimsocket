using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using Steamworks;
using BepInEx;
using BepInEx.Configuration;
using BepInEx.Logging;
using HarmonyLib;
using UnityEngine;

namespace LanBackendBlind
{
    // =====================================================
    // LanBackendBlind - adaptation aux API de l'assembly fourni
    // -----------------------------------------------------------------------
    // Adaptation du transport et du protocole réseau au code fourni :
    //
    // Le client utilise ZNet.Connect(SteamNetworkingIPAddr), le serveur gère
    // les connexions via ZNetPeer, et PeerInfo inclut désormais un champ ticket.
    // =====================================================

    public static class Diagnostics
    {
        public static void Log(string s) => ZLog.Log("[LanBackendBlind] " + s);
        public static void Warn(string s) => ZLog.LogWarning("[LanBackendBlind] " + s);
        public static void Error(string s) => ZLog.LogError("[LanBackendBlind] " + s);
    }

    // -------------------------
    // 1. Disable Steam-only paths replaced by the TCP socket
    // -------------------------
    public static class BackendNeutralizer
    {
        // Apply targeted patches at runtime (safe: check existence first)
        public static void Apply(Harmony harmony)
        {
            TryPatchTypeMethod(harmony, "ZSteamMatchmaking", "RequestSessionTicket");
            TryPatchTypeMethod(harmony, "ZSteamMatchmaking", "RegisterServer");
            TryPatchTypeMethod(harmony, "ZSteamSocket", "StartHost");
        }

        private static void TryPatchTypeMethod(Harmony harmony, string typeName, string methodName)
        {
            try
            {
                var t = AccessTools.TypeByName(typeName);
                if (t == null)
                {
                    Diagnostics.Warn($"Type not found: {typeName}");
                    return;
                }

                MethodBase m = AccessTools.Method(t, methodName);

                if (m == null)
                {
                    // Volontairement gardé en Warn (pas en silencieux/Debug) : c'est
                    // exactement ce niveau de visibilité qui nous a permis de repérer
                    // les incohérences de l'audit précédent. Le rendre silencieux
                    // irait à l'encontre de l'objectif "compatible avec les futures
                    // versions du jeu" — sans ce log, un renommage de méthode dans une
                    // future MAJ casserait silencieusement une neutralisation, sans
                    // aucun moyen de le diagnostiquer.
                    Diagnostics.Warn($"Method not found: {typeName}.{methodName}");
                    return;
                }

                var prefix = new HarmonyMethod(typeof(BackendNeutralizer), nameof(BlockPrefix));
                harmony.Patch(m, prefix: prefix);
                Diagnostics.Log($"Patched: {typeName}.{methodName}");
            }
            catch (Exception ex)
            {
                Diagnostics.Warn($"Patch failed for {typeName}.{methodName} : {ex.Message}");
            }
        }

        // universal prefix that cancels execution
        public static bool BlockPrefix()
        {
            return false;
        }
    }

    // -------------------------
    // Le RPC natif de Valheim lit toujours un champ "ticket". Pour une socket
    // TCP, le ticket est vide et le peer n'est pas un ZSteamSocket. Le helper
    // évite donc le déréférencement nul; la validation native reste active pour
    // les vrais peers Steam.
    [HarmonyPatch(typeof(ZNet), "RPC_PeerInfo", new[] { typeof(ZRpc), typeof(ZPackage) })]
    public static class TcpPeerTicketPatch
    {
        private static readonly MethodInfo s_getPeerId = AccessTools.Method(typeof(ZSteamSocket), "GetPeerID");
        private static readonly MethodInfo s_safeGetPeerId = AccessTools.Method(typeof(TcpPeerTicketPatch), nameof(GetPeerIDOrDefault));

        public static CSteamID GetPeerIDOrDefault(ZSteamSocket socket)
        {
            return socket == null ? default(CSteamID) : socket.GetPeerID();
        }

        [HarmonyTranspiler]
        public static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions)
        {
            bool replaced = false;
            foreach (CodeInstruction instruction in instructions)
            {
                if (s_getPeerId != null && s_safeGetPeerId != null && instruction.Calls(s_getPeerId))
                {
                    instruction.opcode = OpCodes.Call;
                    instruction.operand = s_safeGetPeerId;
                    replaced = true;
                }
                yield return instruction;
            }
            if (!replaced)
                Diagnostics.Error("Transpiler RPC_PeerInfo : appel à ZSteamSocket.GetPeerID introuvable; le handshake TCP ne peut pas éviter le ticket Steam.");
        }
    }

    // Trace côté hôte : distingue une connexion acceptée par ZSocket2 d'un
    // client qui a seulement terminé le handshake TCP Windows.
    [HarmonyPatch(typeof(ZSocket2), "Accept")]
    public static class Diag_ZSocket2_Accept
    {
        [HarmonyPostfix]
        public static void Postfix(ISocket __result)
        {
            if (__result == null) return;
            string remote = "?";
            try { remote = __result.GetHostName(); } catch { }
            Diagnostics.Log("[TCP ACCEPT] connexion acceptée par ZSocket2 depuis " + remote);
        }
    }

    // Trace l'inscription du peer dans le ZNet local, sur hôte et client.
    [HarmonyPatch(typeof(ZNet), "OnNewConnection", new[] { typeof(ZNetPeer) })]
    public static class Diag_ZNet_OnNewConnection
    {
        [HarmonyPrefix]
        public static void Prefix(ZNet __instance, ZNetPeer peer)
        {
            string remote = "?";
            string peerIsServer = peer == null ? "null" : peer.m_server.ToString();
            try { remote = peer?.m_socket?.GetHostName() ?? "?"; } catch { }
            Diagnostics.Log("[PEER REGISTER] localIsServer=" + __instance.IsServer() +
                ", peerIsServer=" + peerIsServer + ", remote=" + remote);
        }

        [HarmonyPostfix]
        public static void Postfix(ZNetPeer peer)
        {
            LanWorldSync.RegisterPeer(peer);
        }
    }

    [HarmonyPatch(typeof(ZSteamMatchmaking), "VerifySessionTicket", new[] { typeof(byte[]), typeof(CSteamID) })]
    public static class TcpSessionTicketPatch
    {
        [HarmonyPrefix]
        public static bool Prefix(byte[] ticket, CSteamID steamID, ref bool __result)
        {
            if (ticket == null || ticket.Length != 0 || steamID != CSteamID.Nil) return true;
            __result = true;
            return false;
        }
    }

    // -------------------------
    // 2. Discovery helpers
    // -------------------------
    public static class LanDiscoveryClient
    {
        public const int DiscoveryPort = 2458;

        public static async Task<(string ip, int port)?> DiscoverServerAsync(int timeoutMs = 800)
        {
            try
            {
                using (UdpClient client = new UdpClient())
                {
                    client.EnableBroadcast = true;
                    byte[] req = Encoding.UTF8.GetBytes("VALHEIM_LAN_PING");
                    await client.SendAsync(req, req.Length, new IPEndPoint(IPAddress.Broadcast, DiscoveryPort));

                    var recvTask = client.ReceiveAsync();
                    if (await Task.WhenAny(recvTask, Task.Delay(timeoutMs)) == recvTask)
                    {
                        var result = recvTask.Result;
                        string text = Encoding.UTF8.GetString(result.Buffer);
                        if (text.StartsWith("VALHEIM_LAN_PONG"))
                        {
                            int port = 2456;
                            int idx = text.IndexOf(':');
                            if (idx >= 0 && int.TryParse(text.Substring(idx + 1), out int parsed))
                                port = parsed;
                            return (result.RemoteEndPoint.Address.ToString(), port);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("DiscoverServerAsync failed: " + ex.Message);
            }
            return null;
        }
    }

    public class LanDiscoveryServer
    {
        private readonly int _listenPort;
        private readonly int _hostPort;
        private UdpClient _udp;
        private volatile bool _running;

        public LanDiscoveryServer(int listenPort, int hostPort)
        {
            _listenPort = listenPort;
            _hostPort = hostPort;
        }

        public void Start()
        {
            try
            {
                _udp = new UdpClient(new IPEndPoint(IPAddress.Any, _listenPort)) { EnableBroadcast = true };
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("Discovery Start failed: " + ex.Message);
                return;
            }

            _running = true;
            Diagnostics.Log($"Discovery listening {_listenPort} announce {_hostPort}");

            Task.Run(async () =>
            {
                while (_running)
                {
                    UdpReceiveResult result;
                    try { result = await _udp.ReceiveAsync(); }
                    catch { break; }

                    string msg;
                    try { msg = Encoding.UTF8.GetString(result.Buffer); }
                    catch { continue; }

                    if (msg == "VALHEIM_LAN_PING")
                    {
                        byte[] reply = Encoding.UTF8.GetBytes("VALHEIM_LAN_PONG:" + _hostPort);
                        try { await _udp.SendAsync(reply, reply.Length, result.RemoteEndPoint); }
                        catch { }
                    }
                }
            });
        }

        public void Stop()
        {
            _running = false;
            try { _udp?.Close(); } catch { }
            _udp = null;
        }
    }

    // -------------------------
    // TCP connector uses Valheim's ZSocket2 framing.
    public class ZConnectorLAN
    {
        private readonly string _host;
        private readonly int _port;
        public ZConnectorLAN(string host, int port) { _host = host; _port = port; }

        public ISocket ConnectBlocking()
        {
            try
            {
                TcpClient client = ZSocket2.CreateSocket();
                var ar = client.BeginConnect(_host, _port, null, null);
                using (var waitHandle = ar.AsyncWaitHandle)
                {
                    if (!waitHandle.WaitOne(TimeSpan.FromSeconds(10)))
                    {
                        client.Close();
                        Diagnostics.Warn($"Connect timeout {_host}:{_port}");
                        return null;
                    }
                }
                client.EndConnect(ar);
                return new ZSocket2(client, _host);
            }
            catch (Exception ex) { Diagnostics.Warn($"ConnectBlocking failed {_host}:{_port} : {ex.Message}"); return null; }
        }
    }

    // -------------------------
    // 4. MainThreadInvoker
    // -------------------------
    public static class MainThreadInvoker
    {
        private const int MaxQueueSize = 1000;
        private static readonly ConcurrentQueue<Action> _queue = new ConcurrentQueue<Action>();
        public static void RunOnMainThread(Action act)
        {
            if (act == null) return;
            if (_queue.Count >= MaxQueueSize)
            {
                Diagnostics.Warn("MainThreadInvoker queue pleine (" + MaxQueueSize + "), action ignorée.");
                return;
            }
            _queue.Enqueue(act);
        }
        public static void Update() { while (_queue.TryDequeue(out var act)) { try { act(); } catch (Exception ex) { Diagnostics.Error(ex.Message); } } }
    }

    // -------------------------
    // 5. ZNet integration (safe reflection)
    // -------------------------
    public static class ZNetLanIntegration
    {
        internal static ZSocket2 s_host;
        internal static LanDiscoveryServer s_discovery;
        private static string s_forcedHost;
        private static int s_forcedPort;

        internal static void SetForcedDestination(string host, int port)
        {
            s_forcedHost = host;
            s_forcedPort = port;
        }

        internal static readonly MethodInfo s_onNewConnection = AccessTools.Method(typeof(ZNet), "OnNewConnection");
        internal static readonly FieldInfo s_connectionStatusField = AccessTools.Field(typeof(ZNet), "m_connectionStatus");
        internal static readonly FieldInfo s_serverSteamIdField = AccessTools.Field(typeof(ZNet), "m_serverSteamID");
        internal static readonly FieldInfo s_publicServerField = AccessTools.Field(typeof(ZNet), "m_publicServer");

        // API v1 : le hash du mot de passe inclut le sel envoyé par l'hôte.
        internal static readonly MethodInfo s_hashPasswordMethod =
            AccessTools.Method(typeof(ZNet), "HashPassword", new[] { typeof(string), typeof(string) });
        internal static readonly MethodInfo s_serverPasswordSaltMethod =
            AccessTools.Method(typeof(ZNet), "ServerPasswordSalt", Type.EmptyTypes);

        // "Version" est une classe interne (internal) du jeu : on récupère son Type
        // directement depuis l'assembly de ZNet (sans ambiguïté possible avec
        // System.Version), puis on lit CurrentVersion (propriété ou champ) par
        // réflexion. Partagé par SendPeerInfo et les patches d'injection de
        // protocole PeerInfo.
        internal static readonly Type s_versionType = typeof(ZNet).Assembly.GetType("Version");

        internal static readonly MethodInfo s_getVersionString =
            s_versionType?.GetMethod("GetVersionString",
                BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic,
                null, Type.EmptyTypes, null)
            ?? AccessTools.Method(s_versionType, "GetVersionString", new[] { typeof(bool) });

        internal static readonly MemberInfo s_currentVersionMember =
            (MemberInfo)s_versionType?.GetProperty("CurrentVersion", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            ?? s_versionType?.GetField("CurrentVersion", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);

        internal static string GetCurrentGameVersionString()
        {
            try
            {
                if (s_getVersionString != null)
                {
                    ParameterInfo[] parameters = s_getVersionString.GetParameters();
                    object[] args = parameters.Length == 0 ? null : new object[] { false };
                    return (string)s_getVersionString.Invoke(null, args);
                }
                object verObj = null;
                if (s_currentVersionMember is PropertyInfo pi) verObj = pi.GetValue(null);
                else if (s_currentVersionMember is FieldInfo fi) verObj = fi.GetValue(null);
                if (verObj != null) return verObj.ToString();
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("Impossible de lire Version.CurrentVersion par réflexion : " + ex.Message);
            }
            return null;
        }

        // Journalise les IP locales de la machine hôte : utile pour comparer avec
        // ce que le client tente de joindre (surtout via Radmin, où l'IP visible
        // par les deux machines doit correspondre à l'adaptateur Radmin).
        internal static void LogLocalIPs(int port)
        {
            try
            {
                var ips = new List<string>();
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                            ips.Add($"{addr.Address} ({ni.Name})");
                    }
                }
                if (ips.Count > 0)
                    Diagnostics.Log("IP(s) locale(s) sur le port " + port + " : " + string.Join(", ", ips));
                else
                    Diagnostics.Warn("Aucune interface réseau IPv4 active détectée sur cette machine !");
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("Impossible d'énumérer les interfaces réseau : " + ex.Message);
            }
        }

        [HarmonyPatch(typeof(ZNet), "Awake")]
        public static class ZNet_Awake_Patch
        {
            [HarmonyPrefix]
            public static void Prefix(ZNet __instance)
            {
                // Clear Steam address selection so ZNet.Start uses its IP path.
                s_serverSteamIdField?.SetValue(null, 0UL);
                s_publicServerField?.SetValue(null, false);
            }

            [HarmonyPostfix]
            public static void Postfix(ZNet __instance)
            {
                if (!__instance.IsServer()) return;

                // Dans l'assembly v1, ZSocket2.StartHost() lit son champ statique
                // s_dataPort (0 par défaut), pas ZNet.m_serverHostPort. Il faut
                // donc appeler SetDataPort avant StartHost, sinon le socket ouvre 0.
                FieldInfo hostPortField = AccessTools.Field(typeof(ZNet), "m_serverHostPort")
                    ?? AccessTools.Field(typeof(ZNet), "m_hostPort");
                int requestedPort = LanBackendPlugin.ManualServerPort?.Value ?? 2456;
                if (requestedPort < 1 || requestedPort > 65535) requestedPort = 2456;
                try
                {
                    MethodInfo setDataPort = AccessTools.Method(typeof(ZSocket2), "SetDataPort", new[] { typeof(int) });
                    if (setDataPort != null)
                    {
                        setDataPort.Invoke(null, new object[] { requestedPort });
                    }
                    else
                    {
                        FieldInfo socketDataPortField = AccessTools.Field(typeof(ZSocket2), "s_dataPort");
                        if (socketDataPortField == null)
                            throw new MissingMemberException("ZSocket2.SetDataPort(int) et ZSocket2.s_dataPort introuvables");
                        socketDataPortField.SetValue(null, requestedPort);
                    }
                    if (hostPortField != null)
                        hostPortField.SetValue(hostPortField.IsStatic ? null : (object)__instance, requestedPort);
                }
                catch (Exception ex)
                {
                    Diagnostics.Error("Impossible de configurer le port TCP hôte " + requestedPort + " : " + ex);
                    return;
                }

                var hostSocket = new ZSocket2();
                if (!hostSocket.StartHost())
                {
                    Diagnostics.Error("ZSocket2 n'a pas pu ouvrir le port TCP " + requestedPort + " (ni les 10 suivants).");
                    return;
                }

                int boundPort = hostSocket.GetHostPort();
                if (boundPort < 1)
                {
                    hostSocket.Dispose();
                    Diagnostics.Error("ZSocket2.StartHost() a réussi mais GetHostPort() a renvoyé " + boundPort +
                        "; socket inutilisable, port demandé=" + requestedPort + ".");
                    return;
                }
                FieldInfo hostSocketField = AccessTools.Field(typeof(ZNet), "m_hostSocket");
                if (hostSocketField == null)
                {
                    hostSocket.Dispose();
                    Diagnostics.Error("Champ ZNet.m_hostSocket introuvable : impossible d'installer ZSocket2.");
                    return;
                }
                try
                {
                    var previousSocket = hostSocketField.GetValue(__instance) as ISocket;
                    hostSocketField.SetValue(__instance, hostSocket);
                    if (previousSocket != null && !ReferenceEquals(previousSocket, hostSocket))
                        previousSocket.Dispose();
                    if (hostPortField != null)
                        hostPortField.SetValue(hostPortField.IsStatic ? null : (object)__instance, boundPort);
                    MethodInfo setDataPort = AccessTools.Method(typeof(ZSocket2), "SetDataPort", new[] { typeof(int) });
                    setDataPort?.Invoke(null, new object[] { boundPort });
                }
                catch (Exception ex)
                {
                    hostSocket.Dispose();
                    Diagnostics.Error("Installation du socket hôte TCP impossible : " + ex);
                    return;
                }

                s_host?.Dispose();
                s_host = hostSocket;

                try
                {
                    s_discovery?.Stop();
                    s_discovery = new LanDiscoveryServer(LanDiscoveryClient.DiscoveryPort, boundPort);
                    s_discovery.Start();
                }
                catch (Exception ex)
                {
                    s_discovery = null;
                    Diagnostics.Warn("Découverte UDP indisponible; connexion manuelle encore possible : " + ex.Message);
                }

                Diagnostics.Log("ZSocket2 host started on TCP port " + boundPort);
                LogLocalIPs(boundPort);
            }
        }

        [HarmonyPatch(typeof(ZNet), "Connect", new[] { typeof(SteamNetworkingIPAddr) })]
        public static class ZNet_Connect_Patch
        {
            [HarmonyPrefix]
            public static bool Prefix(ZNet __instance, SteamNetworkingIPAddr host)
            {
                try
                {
                    s_connectionStatusField?.SetValue(null, ZNet.ConnectionStatus.Connecting);
                    __instance.m_connectingDialog.gameObject.SetActive(true);
                }
                catch (Exception ex) { Diagnostics.Warn("Set connection status failed: " + ex.Message); }

                string endpoint = null;
                try { host.ToString(out endpoint, true); } catch { }
                string connectHost = s_forcedHost;
                int connectPort = s_forcedPort;
                s_forcedHost = null;
                // ManualServerIP force l'adresse LAN/Radmin de l'hôte si elle
                // est configurée; sinon on conserve l'adresse choisie dans le menu.
                if (string.IsNullOrWhiteSpace(connectHost) && !string.IsNullOrWhiteSpace(LanBackendPlugin.ManualServerIP.Value))
                {
                    connectHost = LanBackendPlugin.ManualServerIP.Value;
                    connectPort = LanBackendPlugin.ManualServerPort.Value;
                }
                if (string.IsNullOrWhiteSpace(connectHost) && !string.IsNullOrWhiteSpace(endpoint))
                    ParseHostPort(endpoint, ref connectHost, ref connectPort);
                if (string.IsNullOrWhiteSpace(connectHost))
                {
                    Diagnostics.Warn("Aucune adresse TCP de destination n'est disponible.");
                    s_connectionStatusField?.SetValue(null, ZNet.ConnectionStatus.ErrorConnectFailed);
                    return false;
                }

                Diagnostics.Log($"TCP connect attempt {connectHost}:{connectPort}");

                Task.Run(() =>
                {
                    ISocket sock = new ZConnectorLAN(connectHost, connectPort).ConnectBlocking();
                    MainThreadInvoker.RunOnMainThread(() =>
                    {
                        if (sock == null)
                        {
                            s_connectionStatusField?.SetValue(null, ZNet.ConnectionStatus.ErrorConnectFailed);
                            Diagnostics.Log("TCP connect failed " + connectHost + ":" + connectPort);
                            return;
                        }
                        try
                        {
                            Diagnostics.Log("Socket established, creating ZNetPeer...");
                            ZNetPeer peer = new ZNetPeer(sock, true);
                            s_onNewConnection?.Invoke(__instance, new object[] { peer });
                        }
                        catch (Exception ex) { Diagnostics.Error("Connect error: " + ex.Message); }
                    });
                });

                return false;
            }

            private static void ParseHostPort(string endpoint, ref string host, ref int port)
            {
                string value = endpoint.Trim();
                int separator = value.LastIndexOf(':');
                if (separator > 0 && int.TryParse(value.Substring(separator + 1), out int parsedPort))
                {
                    host = value.Substring(0, separator).Trim('[', ']');
                    port = parsedPort;
                }
                else host = value.Trim('[', ']');
            }
        }

        // Le client atteint bien le listener TCP, mais le chemin natif d'accept
        // ne produisait aucun peer côté hôte dans le test. Pour ZSocket2, on
        // dépile donc explicitement une connexion à chaque poll serveur et on
        // passe le peer à la méthode native d'enregistrement.
        [HarmonyPatch(typeof(ZNet), "CheckForIncommingServerConnections")]
        public static class ZNet_AcceptTcp_Patch
        {
            private static bool s_firstPollLogged;

            [HarmonyPrefix]
            public static bool Prefix(ZNet __instance)
            {
                FieldInfo hostSocketField = AccessTools.Field(typeof(ZNet), "m_hostSocket");
                object currentHostSocket = hostSocketField?.GetValue(__instance);
                if (!s_firstPollLogged)
                {
                    s_firstPollLogged = true;
                    Diagnostics.Log("[HOST ACCEPT POLL] check appelé; m_hostSocket=" +
                        (currentHostSocket == null ? "null" : currentHostSocket.GetType().FullName));
                }

                // Si un autre chemin a remplacé le socket après Awake, réinstalle
                // le listener TCP que ce plugin a ouvert.
                if (hostSocketField != null && s_host != null && !ReferenceEquals(currentHostSocket, s_host))
                {
                    hostSocketField.SetValue(__instance, s_host);
                    currentHostSocket = s_host;
                    Diagnostics.Warn("[HOST ACCEPT POLL] m_hostSocket remplacé; listener ZSocket2 réinstallé.");
                }

                ZSocket2 hostSocket = currentHostSocket as ZSocket2;
                if (hostSocket == null) return true;

                ISocket accepted = null;
                try
                {
                    accepted = hostSocket.Accept();
                    if (accepted == null) return false;
                    if (!accepted.IsConnected())
                    {
                        accepted.Dispose();
                        return false;
                    }

                    ZNetPeer peer = new ZNetPeer(accepted, false);
                    MethodInfo onNewConnection = ZNetLanIntegration.s_onNewConnection;
                    if (onNewConnection == null)
                        throw new MissingMethodException("ZNet.OnNewConnection(ZNetPeer) introuvable");
                    onNewConnection.Invoke(__instance, new object[] { peer });
                    string remote = "?";
                    try { remote = peer.m_socket.GetHostName(); } catch { }
                    Diagnostics.Log("[HOST ACCEPT] peer TCP enregistré depuis " + remote);
                    return false;
                }
                catch (Exception ex)
                {
                    try { accepted?.Dispose(); } catch { }
                    Diagnostics.Error("[HOST ACCEPT] échec de l'enregistrement du peer TCP : " + ex);
                    return false;
                }
            }
        }

        // Réécrit selon le format PeerInfo de l'assembly fourni : le client doit
        // envoyer son hash de mot de passe et un champ de ticket, même en TCP.
        [HarmonyPatch(typeof(ZNet), "SendPeerInfo", new[] { typeof(ZRpc), typeof(string) })]
        public static class Patch_ZNet_SendPeerInfo
        {
            [HarmonyPrefix]
            public static bool Prefix(ZNet __instance, ZRpc rpc, string password)
            {
                ZPackage zpackage = new ZPackage();

                MethodInfo getUid = AccessTools.Method(typeof(ZNet), "GetUID");
                long uid = getUid != null
                    ? (long)getUid.Invoke(getUid.IsStatic ? null : (object)__instance, null)
                    : 0L;
                if (uid == 0L)
                {
                    string hostName = rpc.GetSocket().GetHostName();
                    // Masque de bit plutôt que Math.Abs (évite l'OverflowException
                    // sur int.MinValue et garantit une valeur positive non nulle).
                    uid = hostName.GetHashCode() & 0x7FFFFFFF;
                    if (uid == 0L) uid = 1L;
                }
                zpackage.Write(uid);

                string versionStr = GetCurrentGameVersionString();
                if (string.IsNullOrEmpty(versionStr))
                {
                    Diagnostics.Error("Version du jeu introuvable; le paquet PeerInfo n'est pas envoyé.");
                    return false;
                }
                zpackage.Write(versionStr);
                // Protocole Valheim 1.0 : après GameVersion vient c_networkVersion
                // (UInt32). Sans ce champ, l'hôte lit 0 depuis les octets du Vector3
                // suivant et rejette le peer avec ErrorVersion.
                Type versionType = typeof(ZNet).Assembly.GetType("Version");
                FieldInfo networkVersionField = versionType?.GetField("c_networkVersion",
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                if (networkVersionField == null)
                {
                    Diagnostics.Error("Version.c_networkVersion introuvable; PeerInfo non envoyé.");
                    return false;
                }
                uint networkVersion = Convert.ToUInt32(networkVersionField.GetValue(null));
                zpackage.Write(networkVersion);
                zpackage.Write(__instance.GetReferencePosition());
                zpackage.Write(Game.instance.GetPlayerProfile().GetName());

                // La 1.0 ajoute l'identifiant PlayFab et SimulationDistance avant
                // la branche serveur/client de PeerInfo.
                Type playFabType = typeof(ZNet).Assembly.GetType("PlayFabManager");
                object playFabManager = AccessTools.Property(playFabType, "instance")?.GetValue(null, null);
                string playFabId = AccessTools.Field(playFabType, "PlayFabUniqueId")?.GetValue(playFabManager) as string;
                zpackage.Write(playFabId ?? "");

                MethodInfo getSimulationDistance = AccessTools.Method(typeof(ZNet), "GetDesiredSimulationDistance", Type.EmptyTypes);
                object simulationDistance = getSimulationDistance?.Invoke(__instance, null);
                MethodInfo serializeSimulationDistance = simulationDistance == null ? null :
                    AccessTools.Method(simulationDistance.GetType(), "Serialize", new[] { typeof(ZPackage).MakeByRefType() });
                if (serializeSimulationDistance == null)
                {
                    Diagnostics.Error("SimulationDistance.Serialize(ZPackage&) introuvable; PeerInfo non envoyé.");
                    return false;
                }
                object[] simulationArgs = { zpackage };
                serializeSimulationDistance.Invoke(simulationDistance, simulationArgs);
                zpackage = simulationArgs[0] as ZPackage;
                if (zpackage == null)
                {
                    Diagnostics.Error("SimulationDistance a invalidé le ZPackage; PeerInfo non envoyé.");
                    return false;
                }

                if (__instance.IsServer())
                {
                    World world = AccessTools.Field(typeof(ZNet), "m_world")?.GetValue(null) as World;
                    if (world != null)
                    {
                        zpackage.Write(world.m_name ?? "");
                        zpackage.Write(world.m_seed);
                        zpackage.Write(world.m_seedName ?? "");
                        zpackage.Write(world.m_uid);
                        zpackage.Write(world.m_worldGenVersion);
                    }
                    else
                    {
                        zpackage.Write("");
                        zpackage.Write(0);
                        zpackage.Write("");
                        zpackage.Write(0L);
                        zpackage.Write(0);
                    }
                    zpackage.Write(__instance.GetTimeSeconds());
                }
                else
                {
                    string data = "";
                    MethodInfo hashPassword = ZNetLanIntegration.s_hashPasswordMethod;
                    MethodInfo getPasswordSalt = ZNetLanIntegration.s_serverPasswordSaltMethod;
                    if (!string.IsNullOrEmpty(password) && hashPassword != null && getPasswordSalt != null)
                    {
                        string salt = (string)getPasswordSalt.Invoke(null, null);
                        data = (string)hashPassword.Invoke(null, new object[] { password, salt });
                    }
                    zpackage.Write(data);
                    // Le protocole 1.0 lit ensuite la clé d'invitation, puis le
                    // ticket Steam. Pour TCP direct, la clé est vide et le ticket
                    // vide est accepté par TcpSessionTicketPatch.
                    string inviteSecret = AccessTools.Field(typeof(ZNet), "m_inviteSecretKey")?.GetValue(null) as string;
                    zpackage.Write(inviteSecret ?? "");
                    zpackage.Write(Array.Empty<byte>());
                }

                rpc.Invoke("PeerInfo", new object[] { zpackage });
                Diagnostics.Log("SendPeerInfo (TCP) envoyé, IsServer=" + __instance.IsServer() +
                    ", gameVersion=" + versionStr + ", networkVersion=" + networkVersion);
                return false;
            }
        }

        [HarmonyPatch(typeof(ZNet), "Shutdown")]
        public static class ZNet_Shutdown_Patch
        {
            [HarmonyPostfix]
            public static void Postfix() => StopLan();
        }

        [HarmonyPatch(typeof(ZNet), "OnDestroy")]
        public static class ZNet_OnDestroy_Patch
        {
            [HarmonyPostfix]
            public static void Postfix() => StopLan();
        }

        private static void StopLan()
        {
            // Close est idempotent; couvre aussi le cas où OnDestroy arrive sans Shutdown.
            s_host?.Close();
            s_host = null;
            s_discovery?.Stop();
            s_discovery = null;
        }
    }
    // -------------------------
    // Sondes de handshake (postfix, non-invasif — ne change AUCUN comportement,
    // sert uniquement à savoir où le handshake s'arrête réellement au runtime,
    // au lieu de continuer à deviner par analyse statique).
    // -------------------------
    internal static class HandshakeProbe
    {
        internal static string SafeHostName(ZRpc rpc)
        {
            try { return rpc?.GetSocket()?.GetHostName() ?? "?"; }
            catch { return "?"; }
        }
    }

    // Compare le catalogue des prefabs de Piece enregistrés par chaque joueur,
    // puis demande au ZDOMan natif de prioriser les ZDO de la zone active de l'hôte.
    // Les prefabs/asset bundles restent chargés localement par les mods du client.
    internal static class LanWorldSync
    {
        private const string PieceManifestRpc = "LanBackendBlind.PieceManifest";
        private const int ManifestProtocol = 1;
        private static readonly FieldInfo s_persistentField = FindPersistentField();
        private static readonly PropertyInfo s_persistentProperty = typeof(ZDO).GetProperty(
            "IsPersistent", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        private static readonly MethodInfo s_isPersistentMethod = typeof(ZDO).GetMethod(
            "IsPersistent", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            null, Type.EmptyTypes, null);
        private static bool s_persistenceFallbackLogged;
        private static readonly HashSet<int> s_missingPrefabHashes = new HashSet<int>();
        private static readonly HashSet<long> s_trackingPeers = new HashSet<long>();
        private static DateTime s_lastZdoRxReport = DateTime.MinValue;
        private static int s_zdoRxBatches;
        private static long s_zdoRxBytes;

        internal static void RegisterPeer(ZNetPeer peer)
        {
            try
            {
                if (peer?.m_rpc == null) return;
                peer.m_rpc.Register<ZPackage>(PieceManifestRpc, ReceivePieceManifest);
                Diagnostics.Log("[WORLD SYNC] RPC manifeste Piece enregistré pour le peer.");
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("[WORLD SYNC] Enregistrement du RPC manifeste impossible : " + ex.Message);
            }
        }

        internal static void AfterPeerInfo(ZNet net, ZRpc rpc)
        {
            try
            {
                if (net == null || rpc == null || ZNetScene.instance == null) return;
                ZNetPeer peer = null;
                foreach (ZNetPeer candidate in net.GetPeers())
                {
                    if (candidate != null && candidate.m_rpc == rpc)
                    {
                        peer = candidate;
                        break;
                    }
                }
                if (peer == null || !peer.IsReady()) return;

                SendPieceManifest(rpc);
                if (net.IsServer()) QueueHostActiveZone(net, peer);
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("[WORLD SYNC] Initialisation de la synchronisation monde impossible : " + ex);
            }
        }

        private static Dictionary<string, int> GetLocalPieceManifest()
        {
            Dictionary<string, int> result = new Dictionary<string, int>(StringComparer.Ordinal);
            ZNetScene scene = ZNetScene.instance;
            if (scene == null || scene.m_prefabs == null) return result;

            foreach (GameObject prefab in scene.m_prefabs)
            {
                if (prefab == null || prefab.GetComponent<Piece>() == null) continue;
                string name = prefab.name;
                if (!string.IsNullOrEmpty(name)) result[name] = scene.GetPrefabHash(prefab);
            }
            return result;
        }

        private static void SendPieceManifest(ZRpc rpc)
        {
            Dictionary<string, int> manifest = GetLocalPieceManifest();
            ZPackage package = new ZPackage();
            package.Write(ManifestProtocol);
            package.Write(manifest.Count);
            foreach (KeyValuePair<string, int> entry in manifest)
            {
                package.Write(entry.Key);
                package.Write(entry.Value);
            }
            rpc.Invoke(PieceManifestRpc, new object[] { package });
            Diagnostics.Log("[WORLD SYNC] Manifeste Piece envoyé : " + manifest.Count + " prefabs.");
        }

        private static void ReceivePieceManifest(ZRpc rpc, ZPackage package)
        {
            try
            {
                int protocol = package.ReadInt();
                int count = package.ReadInt();
                if (protocol != ManifestProtocol || count < 0 || count > 50000)
                {
                    Diagnostics.Warn("[WORLD SYNC] Manifeste Piece invalide : protocole=" + protocol + ", count=" + count);
                    return;
                }

                Dictionary<string, int> local = GetLocalPieceManifest();
                List<string> missing = new List<string>();
                int mismatched = 0;
                for (int i = 0; i < count; i++)
                {
                    string name = package.ReadString();
                    int remoteHash = package.ReadInt();
                    int localHash;
                    if (!local.TryGetValue(name, out localHash)) missing.Add(name + " [hash=" + remoteHash + "]");
                    else if (localHash != remoteHash) mismatched++;
                }

                string side = ZNet.instance != null && ZNet.instance.IsServer()
                    ? "manquants chez le client"
                    : "manquants localement (présents chez l'hôte)";
                Diagnostics.Log("[WORLD SYNC] Manifeste distant reçu : " + count + " prefabs; " +
                    missing.Count + " " + side + "; hashes différents=" + mismatched + ".");
                int logged = Math.Min(missing.Count, 30);
                for (int i = 0; i < logged; i++) Diagnostics.Warn("[WORLD SYNC] Prefab absent : " + missing[i]);
                if (missing.Count > logged)
                    Diagnostics.Warn("[WORLD SYNC] ... et " + (missing.Count - logged) + " autres prefabs absents.");
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("[WORLD SYNC] Lecture du manifeste Piece impossible : " + ex.Message);
            }
        }

        private static void QueueHostActiveZone(ZNet net, ZNetPeer peer)
        {
            if (ZoneSystem.instance == null || ZDOMan.instance == null) return;
            Vector3 clientPosition = peer.GetRefPos();
            object clientZone = GetZone(clientPosition);
            int queued = QueueZoneZdos(peer, clientZone, true);
            Diagnostics.Log("[WORLD SYNC] Zone initiale du client : " + queued +
                " ZDO persistants de pièces mis en file à " + clientPosition + ".");

            // Les constructions autour du point de spawn doivent aussi être
            // disponibles pour un personnage qui reprend sa partie ailleurs.
            object spawnZone = GetZone(Vector3.zero);
            if (!object.Equals(spawnZone, clientZone))
            {
                int spawnQueued = QueueZoneZdos(peer, spawnZone, true);
                Diagnostics.Log("[WORLD SYNC] Zone du spawn : " + spawnQueued +
                    " ZDO persistants de pièces mis en file.");
            }

            // La position de référence du peer est actualisée par le protocole
            // natif. Lorsqu'il entre dans un autre secteur, on force l'envoi de
            // ses ZDO sans déplacer la zone active de l'hôte.
            if (s_trackingPeers.Add(peer.m_uid))
                net.StartCoroutine(TrackClientZones(net, peer, clientZone));

            if (LanBackendPlugin.PrefetchPersistentBuildZdos?.Value ?? true)
            {
                List<ZDOID> buildSnapshot = CollectPersistentBuildZdos();
                if (buildSnapshot != null)
                {
                    Diagnostics.Log("[WORLD SYNC] Snapshot de monde : " + buildSnapshot.Count +
                        " ZDO persistants de pièces à précharger en arrière-plan.");
                    net.StartCoroutine(QueueBuildSnapshot(peer, buildSnapshot));
                }
            }
        }

        private static IEnumerator TrackClientZones(ZNet net, ZNetPeer peer, object previousZone)
        {
            long peerId = peer.m_uid;
            while (net != null && net.IsServer() && peer != null && peer.IsReady() &&
                peer.m_rpc != null && peer.m_rpc.IsConnected())
            {
                yield return new WaitForSeconds(2f);
                if (net == null || !net.IsServer() || peer == null || !peer.IsReady() ||
                    peer.m_rpc == null || !peer.m_rpc.IsConnected()) break;

                try
                {
                    Vector3 position = peer.GetRefPos();
                    object currentZone = GetZone(position);
                    if (object.Equals(currentZone, previousZone)) continue;

                    int queued = QueueZoneZdos(peer, currentZone, true);
                    Diagnostics.Log("[WORLD SYNC] Changement de secteur client : " + queued +
                        " ZDO persistants de pièces mis en file à " + position + ".");
                    previousZone = currentZone;
                }
                catch (Exception ex)
                {
                    Diagnostics.Warn("[WORLD SYNC] Suivi du secteur client impossible : " + ex.Message);
                }
            }
            s_trackingPeers.Remove(peerId);
        }

        private static object GetZone(Vector3 position)
        {
            MethodInfo method = AccessTools.Method(typeof(ZoneSystem), "GetZone", new[] { typeof(Vector3) });
            if (method == null) throw new MissingMethodException("ZoneSystem.GetZone(Vector3)");
            return method.Invoke(method.IsStatic ? null : (object)ZoneSystem.instance, new object[] { position });
        }

        private static int QueueZoneZdos(ZNetPeer peer, object zone, bool buildPiecesOnly)
        {
            List<ZDO> objects = new List<ZDO>();
            FindSectorObjects(zone, objects);
            int queued = 0;
            foreach (ZDO zdo in objects)
            {
                if (zdo == null) continue;
                if (buildPiecesOnly)
                {
                    if (!IsPersistent(zdo)) continue;
                    GameObject prefab = ZNetScene.instance.GetPrefab(zdo.GetPrefab());
                    if (prefab == null || prefab.GetComponent<Piece>() == null) continue;
                }
                ZDOMan.instance.ForceSendZDO(peer.m_uid, zdo.m_uid);
                queued++;
            }
            return queued;
        }

        private static void FindSectorObjects(object zone, List<ZDO> objects)
        {
            MethodInfo getDistance = AccessTools.Method(typeof(ZNet), "GetDesiredSimulationDistance", Type.EmptyTypes);
            object distance = getDistance?.Invoke(ZNet.instance, null);
            object activeArea = ReadZoneSystemValue("m_activeArea");
            object distantArea = ReadZoneSystemValue("m_activeDistantArea");

            MethodInfo[] methods = typeof(ZDOMan).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            foreach (MethodInfo method in methods)
            {
                if (method.Name != "FindSectorObjects") continue;
                ParameterInfo[] parameters = method.GetParameters();
                if (parameters.Length == 3 && parameters[0].ParameterType.IsInstanceOfType(zone) &&
                    parameters[2].ParameterType == typeof(List<ZDO>))
                {
                    object area = CoerceSectorArgument(parameters[1].ParameterType, distance, activeArea);
                    if (area == null) continue;
                    method.Invoke(ZDOMan.instance, new[] { zone, area, (object)objects });
                    return;
                }

                if (parameters.Length == 4 && parameters[0].ParameterType.IsInstanceOfType(zone) &&
                    parameters[2].ParameterType == typeof(List<ZDO>) &&
                    parameters[3].ParameterType == typeof(List<ZDO>))
                {
                    object simulationDistance = CoerceSectorArgument(parameters[1].ParameterType, distance, activeArea);
                    if (simulationDistance == null) continue;

                    List<ZDO> distantObjects = new List<ZDO>();
                    method.Invoke(ZDOMan.instance,
                        new[] { zone, simulationDistance, (object)objects, (object)distantObjects });
                    HashSet<ZDOID> seen = new HashSet<ZDOID>();
                    foreach (ZDO zdo in objects)
                        if (zdo != null) seen.Add(zdo.m_uid);
                    foreach (ZDO zdo in distantObjects)
                        if (zdo != null && seen.Add(zdo.m_uid)) objects.Add(zdo);
                    return;
                }

                if (parameters.Length == 5 && parameters[0].ParameterType.IsInstanceOfType(zone) &&
                    parameters[3].ParameterType == typeof(List<ZDO>) &&
                    parameters[4].ParameterType == typeof(List<ZDO>))
                {
                    object area = CoerceSectorArgument(parameters[1].ParameterType, distance, activeArea);
                    object distant = CoerceSectorArgument(parameters[2].ParameterType, distance, distantArea);
                    if (area == null || distant == null) continue;
                    method.Invoke(ZDOMan.instance, new[] { zone, area, distant, (object)objects, null });
                    return;
                }
            }
            throw new MissingMethodException("ZDOMan.FindSectorObjects compatible avec le type de zone " +
                (zone?.GetType().FullName ?? "null") + "; signatures trouvées: " +
                string.Join(" | ", Array.ConvertAll(methods, m => m.Name == "FindSectorObjects" ?
                    string.Join(",", Array.ConvertAll(m.GetParameters(), p => p.ParameterType.Name)) : null)
                    .Where(s => s != null).ToArray()));
        }

        private static object ReadZoneSystemValue(string name)
        {
            if (ZoneSystem.instance == null) return null;
            FieldInfo field = AccessTools.Field(typeof(ZoneSystem), name);
            if (field != null) return field.GetValue(ZoneSystem.instance);
            PropertyInfo property = AccessTools.Property(typeof(ZoneSystem), name);
            return property?.GetValue(ZoneSystem.instance, null);
        }

        private static object CoerceSectorArgument(Type targetType, object desiredDistance, object zoneValue)
        {
            if (desiredDistance != null && targetType.IsInstanceOfType(desiredDistance)) return desiredDistance;
            if (zoneValue != null && targetType.IsInstanceOfType(zoneValue)) return zoneValue;
            if (zoneValue == null) return null;
            try
            {
                Type effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;
                if (effectiveType.IsEnum) return Enum.ToObject(effectiveType, zoneValue);
                return Convert.ChangeType(zoneValue, effectiveType);
            }
            catch { return null; }
        }

        private static List<ZDOID> CollectPersistentBuildZdos()
        {
            try
            {
                ZDOMan manager = ZDOMan.instance;
                if (manager == null) return null;
                Dictionary<string, int> manifest = GetLocalPieceManifest();
                HashSet<int> pieceHashes = new HashSet<int>(manifest.Values);
                FieldInfo objectsField = AccessTools.Field(typeof(ZDOMan), "m_objectsByID");
                IDictionary objects = objectsField?.GetValue(manager) as IDictionary;
                if (objects == null)
                {
                    Diagnostics.Warn("[WORLD SYNC] Snapshot global impossible : ZDOMan.m_objectsByID introuvable.");
                    return null;
                }

                List<ZDOID> result = new List<ZDOID>();
                foreach (DictionaryEntry entry in objects)
                {
                    ZDO zdo = entry.Value as ZDO;
                    if (zdo != null && IsPersistent(zdo) && pieceHashes.Contains(zdo.GetPrefab()))
                        result.Add(zdo.m_uid);
                }
                return result;
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("[WORLD SYNC] Collecte du snapshot des constructions impossible : " + ex.Message);
                return null;
            }
        }

        private static bool IsPersistent(ZDO zdo)
        {
            try
            {
                if (s_persistentField != null) return Convert.ToBoolean(s_persistentField.GetValue(zdo));
                if (s_persistentProperty != null) return Convert.ToBoolean(s_persistentProperty.GetValue(zdo, null));
                if (s_isPersistentMethod != null) return Convert.ToBoolean(s_isPersistentMethod.Invoke(zdo, null));

                // Certaines versions ne publient plus le flag persistent sur ZDO.
                // Ici, l'appelant vérifie aussi que le prefab est une Piece : on
                // préfère envoyer cette pièce plutôt que de l'exclure silencieusement.
                if (!s_persistenceFallbackLogged)
                {
                    s_persistenceFallbackLogged = true;
                    Diagnostics.Warn("[WORLD SYNC] Aucun indicateur de persistance trouvé sur ZDO; " +
                        "les ZDO de prefabs Piece seront considérés comme persistants pour le préchargement ciblé.");
                }
                return true;
            }
            catch (Exception ex)
            {
                Diagnostics.Warn("[WORLD SYNC] Lecture de la persistance ZDO impossible; la pièce sera incluse : " + ex.Message);
                return true;
            }
        }

        private static FieldInfo FindPersistentField()
        {
            BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            string[] names = { "m_persistent", "m_isPersistent", "m_persistentData" };
            foreach (string name in names)
            {
                FieldInfo field = typeof(ZDO).GetField(name, flags);
                if (field != null && (field.FieldType == typeof(bool) || field.FieldType == typeof(byte))) return field;
            }
            return null;
        }

        private static IEnumerator QueueBuildSnapshot(ZNetPeer peer, List<ZDOID> zdoIds)
        {
            const int idsPerFrame = 16;
            int queued = 0;
            foreach (ZDOID id in zdoIds)
            {
                if (peer == null || !peer.IsReady() || peer.m_rpc == null || !peer.m_rpc.IsConnected())
                    yield break;
                ZDOMan manager = ZDOMan.instance;
                if (manager == null) yield break;
                manager.ForceSendZDO(peer.m_uid, id);
                queued++;
                if (queued % idsPerFrame == 0) yield return null;
            }
            Diagnostics.Log("[WORLD SYNC] Snapshot terminé : " + queued +
                " ZDO persistants de constructions placés dans la file native pour " + peer.m_playerName + ".");
        }

        internal static void ReportZdoData(ZPackage package)
        {
            if (package == null) return;
            s_zdoRxBatches++;
            s_zdoRxBytes += package.Size();
            DateTime now = DateTime.UtcNow;
            if ((now - s_lastZdoRxReport).TotalSeconds >= 15.0)
            {
                Diagnostics.Log("[ZDO RX] sur 15 s : " + s_zdoRxBatches +
                    " paquets, " + s_zdoRxBytes + " octets reçus.");
                s_zdoRxBatches = 0;
                s_zdoRxBytes = 0;
                s_lastZdoRxReport = now;
            }
        }

        internal static void ReportMissingPrefab(ZDO zdo)
        {
            if (zdo == null) return;
            int hash = zdo.GetPrefab();
            if (!s_missingPrefabHashes.Add(hash)) return;
            Diagnostics.Warn("[ZDO SPAWN] prefab absent côté local : hash=" + hash +
                ", zdo=" + zdo.m_uid + ", position=" + zdo.GetPosition() +
                ". Le ZDO est reçu mais son mod/prefab n'est pas enregistré dans ZNetScene.");
        }
    }

    [HarmonyPatch(typeof(ZDOMan), "RPC_ZDOData", new[] { typeof(ZRpc), typeof(ZPackage) })]
    public static class Diag_ZDOMan_RPC_ZDOData
    {
        [HarmonyPrefix]
        public static void Prefix(ZPackage pkg) => LanWorldSync.ReportZdoData(pkg);
    }

    [HarmonyPatch(typeof(ZNetScene), "CreateObject", new[] { typeof(ZDO) })]
    public static class Diag_ZNetScene_CreateObject
    {
        [HarmonyPostfix]
        public static void Postfix(ZDO zdo, GameObject __result)
        {
            if (__result != null) return;
            ZNetScene scene = ZNetScene.instance;
            if (zdo != null && (scene == null || scene.GetPrefab(zdo.GetPrefab()) == null))
                LanWorldSync.ReportMissingPrefab(zdo);
        }
    }

    [HarmonyPatch(typeof(ZNet), "RPC_ServerHandshake", new[] { typeof(ZRpc), typeof(string) })]
    public static class Diag_RPC_ServerHandshake
    {
        [HarmonyPostfix]
        public static void Postfix(ZNet __instance, ZRpc rpc, string secretKey)
        {
            Diagnostics.Log("[HANDSHAKE] RPC_ServerHandshake reçu par " +
                (__instance.IsServer() ? "le SERVEUR" : "?") + " depuis " + HandshakeProbe.SafeHostName(rpc));
        }
    }

    [HarmonyPatch(typeof(ZNet), "RPC_ClientHandshake", new[] { typeof(ZRpc), typeof(bool), typeof(string) })]
    public static class Diag_RPC_ClientHandshake
    {
        [HarmonyPostfix]
        public static void Postfix(ZNet __instance, ZRpc rpc, bool needPassword, string serverPasswordSalt)
        {
            Diagnostics.Log("[HANDSHAKE] RPC_ClientHandshake reçu par le CLIENT, needPassword=" + needPassword);
        }
    }

    [HarmonyPatch(typeof(ZNet), "RPC_PeerInfo", new[] { typeof(ZRpc), typeof(ZPackage) })]
    public static class Diag_RPC_PeerInfo
    {
        [HarmonyPostfix]
        public static void Postfix(ZNet __instance, ZRpc rpc)
        {
            // NB : RPC_PeerInfo peut retourner tôt en cas de refus (mot de passe,
            // liste noire, serveur plein, déjà connecté...) — ce postfix s'exécute
            // dans tous les cas. Si le peer est réellement accepté, il apparaît juste
            // après dans la liste des joueurs ; sinon regardez juste au-dessus dans
            // le log la vraie raison du jeu ("has wrong password", "is blacklisted",
            // "disconnected due to server is full", "Already connected to peer"...).
            Diagnostics.Log("[HANDSHAKE] RPC_PeerInfo exécuté par " +
                (__instance.IsServer() ? "le SERVEUR" : "le CLIENT") + ", depuis " + HandshakeProbe.SafeHostName(rpc) +
                " — vérifiez la ligne juste au-dessus pour un éventuel refus (mot de passe / liste noire / serveur plein).");
            LanWorldSync.AfterPeerInfo(__instance, rpc);
        }
    }

    // -------------------------
    // 8. Plugin entry
    // -------------------------
    [BepInPlugin("com.lan.backend.blind", "LanBackendBlind", "3.1.4")]
    public class LanBackendPlugin : BaseUnityPlugin
    {
        internal static ManualLogSource Log;
        internal static ConfigEntry<string> ManualServerIP;
        internal static ConfigEntry<int> ManualServerPort;
        internal static ConfigEntry<bool> PrefetchPersistentBuildZdos;

        private void Awake()
        {
            try
            {
                AwakeInternal();
            }
            catch (Exception ex)
            {
                // Filet de sécurité ultime : si N'IMPORTE QUOI plante dans Awake() (même
                // un cas qu'on n'a pas anticipé), on le journalise au lieu de laisser
                // l'exception remonter en silence — c'est précisément ce silence total
                // qui a rendu le diagnostic du problème "serveur dédié" aussi long.
                try { Logger.LogFatal("[LanBackendBlind] Awake() a levé une exception non gérée : " + ex); }
                catch { }
                try { UnityEngine.Debug.LogError("[LanBackendBlind] Awake() FATAL: " + ex); }
                catch { }
            }
        }

        private void AwakeInternal()
        {
            Log = Logger;
            ManualServerIP = Config.Bind(
                "LanBackendBlind",
                "ManualServerIP",
                "",
                "Adresse LAN/Radmin de l'hôte (IP ou nom DNS, sans port). " +
                "Vide = utiliser l'adresse choisie dans Valheim.");
            ManualServerPort = Config.Bind(
                "LanBackendBlind",
                "ManualServerPort",
                2456,
                "Port TCP de l'hôte LAN/Radmin indiqué par ManualServerIP.");
            PrefetchPersistentBuildZdos = Config.Bind(
                "LanBackendBlind",
                "PrefetchPersistentBuildZdos",
                false,
                "Option expérimentale : précharge tous les ZDO persistants de construction du monde à la connexion.");

            var harmony = new Harmony("com.lan.backend.blind");

            // Apply targeted patches via BackendNeutralizer.Apply (safe)
            try
            {
                BackendNeutralizer.Apply(harmony);
            }
            catch (Exception ex) { Diagnostics.Warn("BackendNeutralizer.Apply failed: " + ex.Message); }

            // Applique les patches par classe pour isoler une cible Harmony qui aurait
            // changé de signature dans l'assembly chargé.
            PatchAllSafely(harmony);

            // Log patched methods (best-effort)
            try
            {
                foreach (var method in Harmony.GetAllPatchedMethods())
                {
                    Logger.LogInfo("[LAN] Patched: " + method.DeclaringType.FullName + "." + method.Name);
                }
            }
            catch { }

            // Vérifie au chargement les points d'accroche réflexifs utilisés par le mod.
            try
            {
                CheckReflectionTarget("ZNet.OnNewConnection", ZNetLanIntegration.s_onNewConnection);
                CheckReflectionTarget("ZNet.m_connectionStatus", ZNetLanIntegration.s_connectionStatusField);
                CheckReflectionTarget("ZNet.m_serverSteamID", ZNetLanIntegration.s_serverSteamIdField);
                CheckReflectionTarget("ZNet.m_publicServer", ZNetLanIntegration.s_publicServerField);
                CheckReflectionTarget("ZNet.HashPassword(string,string)", ZNetLanIntegration.s_hashPasswordMethod);
                CheckReflectionTarget("ZNet.ServerPasswordSalt()", ZNetLanIntegration.s_serverPasswordSaltMethod);
                CheckReflectionTarget("Version (type)", ZNetLanIntegration.s_versionType);
                CheckReflectionTarget("Version.GetVersionString overload", ZNetLanIntegration.s_getVersionString);
            }
            catch { }

            Diagnostics.Log("LanBackendBlind loaded.");
        }

        private static void PatchAllSafely(Harmony harmony)
        {
            int patched = 0, skipped = 0, failed = 0;
            foreach (var type in GetLoadableTypes(Assembly.GetExecutingAssembly()))
            {
                try
                {
                    var result = harmony.CreateClassProcessor(type).Patch();
                    if (result != null && result.Count > 0) patched++;
                    else skipped++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Diagnostics.Warn($"Échec isolé sur '{type.FullName}': {ex.Message} (les autres patches continuent).");
                }
            }
            Diagnostics.Log($"PatchAllSafely: {patched} classes patchées, {skipped} sans rapport, {failed} échec(s) isolé(s).");
        }

        // Récupère les types chargés si un type annexe échoue à la résolution.
        private static Type[] GetLoadableTypes(Assembly assembly)
        {
            try
            {
                return assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                var loaded = new List<Type>();
                foreach (var t in ex.Types)
                {
                    if (t != null) loaded.Add(t);
                }
                Diagnostics.Warn($"Assembly.GetTypes() a échoué partiellement : {loaded.Count} type(s) chargé(s) sur {ex.Types.Length}.");
                return loaded.ToArray();
            }
        }

        private static void CheckReflectionTarget(string label, object member)
        {
            if (member == null) Diagnostics.Warn("Cible de réflexion manquante : " + label);
            else Diagnostics.Log("OK : " + label);
        }

        private bool m_f9WasDown;

        private void Update()
        {
            MainThreadInvoker.Update();

            // F9 lance la découverte LAN puis utilise ManualServerIP si aucun hôte
            // n'est annoncé. L'adresse Radmin doit être celle de l'hôte, pas celle
            // de l'adaptateur local du client.
            bool f9Down = Input.GetKey(KeyCode.F9);
            if (f9Down && !m_f9WasDown)
            {
                TryDirectJoin();
            }
            m_f9WasDown = f9Down;
        }

        private static void TryDirectJoin()
        {
            if (FejdStartup.instance == null)
            {
                Diagnostics.Warn("F9 pressé mais FejdStartup.instance est null (pas dans le menu de démarrage).");
                return;
            }
            FejdStartup startup = FejdStartup.instance;
            string host = ManualServerIP.Value;
            int port = ManualServerPort.Value;

            Task.Run(async () =>
            {
                if (string.IsNullOrWhiteSpace(host))
                {
                    try
                    {
                        var discovered = await LanDiscoveryClient.DiscoverServerAsync();
                        if (discovered.HasValue)
                        {
                            host = discovered.Value.ip;
                            port = discovered.Value.port;
                            Diagnostics.Log("F9 discovery found " + host + ":" + port);
                        }
                    }
                    catch (Exception ex) { Diagnostics.Warn("F9 discovery failed: " + ex.Message); }
                }

                MainThreadInvoker.RunOnMainThread(() =>
                {
                    if (string.IsNullOrWhiteSpace(host))
                    {
                        Diagnostics.Warn("F9 : configure ManualServerIP avec l'adresse Radmin de l'hôte, ou vérifie la découverte LAN.");
                        return;
                    }
                    if (startup == null) return;

                    Diagnostics.Log("F9 : connexion TCP forcée vers " + host + ":" + port);
                    ZNetLanIntegration.SetForcedDestination(host, port);
                    ZNet.SetServer(false, false, false, "", "", null);
                    ZNet.ResetServerHost();
                    try
                    {
                        MethodInfo transition = AccessTools.Method(typeof(FejdStartup), "TransitionToMainScene");
                        if (transition == null) throw new MissingMethodException("FejdStartup.TransitionToMainScene");
                        transition.Invoke(startup, null);
                    }
                    catch (Exception ex) { Diagnostics.Error("F9 : transition vers le jeu impossible : " + ex); }
                });
            });
        }
    }
}
