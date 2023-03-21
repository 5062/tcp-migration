import array
from typing import List, Dict, Tuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, DEAD_DISPATCHER, \
    HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib import snortlib
from ryu.lib.packet import ether_types, packet, ethernet, ipv4, tcp, in_proto, arp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPAction, OFPMatch
from ryu.utils import hex_array

from tcp_util import TcpEndpoint, format_tcp, build_tcp, TcpConn
import timeit


class TcpMigrationDp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[str, Datapath] = {}
        self.snort = kwargs['snortlib']
        self.snort_port = 4
        socket_config = {'unixsock': True}

        self.mac_to_port: Dict[str, Dict[str, int]] = {}
        self.backend_mac_to_port: Dict[int, Dict[str, int]] = {
            1: {
                '00:00:00:00:00:01': 2,
            }
        }
        self.backend_ports = [2]
        self.tcp_connections: Dict[Tuple[str, int, str, int], TcpConn] = {}
        self.tcp_connections_migrated: Dict[Tuple[str, int, str, int], TcpConn] = {}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        self.logger.error(f'OFPErrorMsg received: type={ev.msg.type} code={ev.msg.code} '
                          f'message={hex_array(ev.msg.data)}')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, table_id=0, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.warn(f'packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes')

        datapath: Datapath = ev.msg.datapath
        dpid: str = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port: int = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        pkt_eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)

        # ignore lldp packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        # ignore ipv6 packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        self.logger.info(f'packet_in dpid={datapath.id} src={pkt_eth.src} dst={pkt_eth.dst} '
                         f'in_port={in_port}')

        self.mac_to_port.setdefault(dpid, {})
        if in_port not in self.backend_ports:
            self.mac_to_port[dpid][pkt_eth.src] = in_port

        if pkt_eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][pkt_eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        pkt_ipv4: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp: tcp.tcp = pkt.get_protocol(tcp.tcp)

        if pkt_ipv4 and pkt_tcp:
            tcp_id = (pkt_ipv4.dst, pkt_tcp.dst_port, pkt_ipv4.src, pkt_tcp.src_port)
            tcp_reverse_id = (pkt_ipv4.src, pkt_tcp.src_port, pkt_ipv4.dst, pkt_tcp.dst_port)

            self.logger.info(f'Packet in {format_tcp(pkt)}')

            if tcp_id in self.tcp_connections:
                tcp_conn = self.tcp_connections[tcp_id]

                # first data packet from client: send to snort and save
                if pkt_tcp.bits == (tcp.TCP_PSH | tcp.TCP_ACK) and pkt_tcp.seq == (
                        tcp_conn.src_isn + 1):
                    self.logger.info('PSH/ACK received...')
                    # ignore duplicate packets
                    # the latency introduced in snort analysis causes client side retransmission
                    if tcp_conn.last_received_seq == pkt_tcp.seq:
                        return
                    tcp_conn.last_received_seq = pkt_tcp.seq
                    self.logger.info('Sending out PSH/ACK...')
                    global start
                    start = timeit.default_timer()
                    self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)

                    tcp_conn.data_pkt = pkt
                    return

            elif tcp_reverse_id in self.tcp_connections_migrated:
                tcp_conn = self.tcp_connections[tcp_reverse_id]
                tcp_conn_migrated = self.tcp_connections_migrated[tcp_reverse_id]

                # SYN-ACK from server 2: record ISN, send ACK response, add flow rules for seq/ack
                # synchronization, release data packet and close original connection
                if pkt_tcp.bits == tcp.TCP_SYN | tcp.TCP_ACK:
                    tcp_conn_migrated.dst_isn = pkt_tcp.seq

                    self.tcp_migrate_handle_synack(datapath, tcp_conn=tcp_conn,
                                                   tcp_conn_migrated=tcp_conn_migrated)
                    return

            elif tcp_reverse_id in self.tcp_connections:
                tcp_conn = self.tcp_connections[tcp_reverse_id]

                # SYN-ACK from server 1: record ISN and forward
                if pkt_tcp.bits == tcp.TCP_SYN | tcp.TCP_ACK:
                    tcp_conn.dst_isn = pkt_tcp.seq

                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    return

            else:
                # SYN from client: initialize TcpConn and forward
                if pkt_tcp.bits == tcp.TCP_SYN:
                    tcp_conn = TcpConn(dst=TcpEndpoint(pkt_eth.dst, pkt_ipv4.dst, pkt_tcp.dst_port),
                                       src=TcpEndpoint(pkt_eth.src, pkt_ipv4.src, pkt_tcp.src_port),
                                       src_isn=pkt_tcp.seq)

                    self.tcp_connections[tcp_id] = tcp_conn

                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    return
        # endif pkt_ipv4 and pkt_tcp

        pkt_arp: arp.arp = pkt.get_protocol(arp.arp)

        if pkt_arp:
            if pkt_arp.dst_mac in self.backend_mac_to_port[dpid]:
                backend_out_port = self.backend_mac_to_port[dpid][pkt_arp.dst_mac]
                actions: List[OFPAction] = [parser.OFPActionOutput(port=out_port),
                                            parser.OFPActionOutput(port=backend_out_port)]
                self.send_packet_out(datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                     in_port=ofproto.OFPP_CONTROLLER, actions=actions, pkt=pkt)
                return

        self.send_packet_out(datapath, out_port=out_port, pkt=pkt)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        self.logger.info('OFPBarrierReply received')

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def alert_handler(self, ev):
        datapath = next(iter(self.datapaths.values()))
        dpid = int(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(array.array('B', ev.msg.pkt))
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        # type(ev.msg.alertmsg) is tuple(bytes,)
        alert_msg: str = ev.msg.alertmsg[0].decode('utf-8')

        if pkt_ipv4 and pkt_tcp:
            tcp_id = (pkt_ipv4.dst, pkt_tcp.dst_port, pkt_ipv4.src, pkt_tcp.src_port)

            if tcp_id not in self.tcp_connections:
                return
            tcp_conn = self.tcp_connections[tcp_id]

            # ignore duplicate alerts
            if tcp_conn.last_event_seq == pkt_tcp.seq:
                return
            tcp_conn.last_event_seq = pkt_tcp.seq

            self.logger.info(f'snort alert: {alert_msg}')

            if alert_msg.startswith('MIGRATE'):
                tcp_conn_migrated = self.tcp_migrate_start(datapath=datapath, src=tcp_conn.src,
                                                           dst=tcp_conn.dst, isn=tcp_conn.src_isn)

                self.tcp_connections_migrated[tcp_id] = tcp_conn_migrated

                return

            elif alert_msg.startswith('FORWARD'):
                # add flow rules for forwarding
                out_port = self.mac_to_port[dpid][tcp_conn.dst.mac]
                match: OFPMatch = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                  ipv4_src=tcp_conn.src.ipv4,
                                                  ipv4_dst=tcp_conn.dst.ipv4,
                                                  ip_proto=in_proto.IPPROTO_TCP,
                                                  tcp_src=tcp_conn.src.tcp_port,
                                                  tcp_dst=tcp_conn.dst.tcp_port
                                                  )

                actions = [parser.OFPActionOutput(port=out_port)]

                self.add_flow(datapath, table_id=0, priority=10, match=match, actions=actions)

                reverse_out_port = self.mac_to_port[dpid][tcp_conn.src.mac]
                reverse_match: OFPMatch = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                          ipv4_src=tcp_conn.dst.ipv4,
                                                          ipv4_dst=tcp_conn.src.ipv4,
                                                          ip_proto=in_proto.IPPROTO_TCP,
                                                          tcp_src=tcp_conn.dst.tcp_port,
                                                          tcp_dst=tcp_conn.src.tcp_port
                                                          )

                reverse_actions = [parser.OFPActionOutput(port=reverse_out_port)]

                self.add_flow(datapath, table_id=0, priority=10, match=reverse_match,
                              actions=reverse_actions)

                # send original data packet
                data_pkt = tcp_conn.data_pkt
                self.send_packet_out(datapath, out_port=out_port, pkt=data_pkt)

    def tcp_migrate_start(self, datapath: Datapath, src: TcpEndpoint, dst: TcpEndpoint, isn: int) \
            -> TcpConn:
        dpid = datapath.id

        self.backend_mac_to_port.setdefault(dpid, {})
        out_port = self.backend_mac_to_port[dpid][dst.mac]

        syn = build_tcp(dst=dst, src=src, seq=isn, flags=tcp.TCP_SYN)

        self.send_packet_out(datapath, out_port=out_port, pkt=syn)

        tcp_conn = TcpConn(dst=dst, src=src)
        return tcp_conn

    def tcp_migrate_handle_synack(self, datapath: Datapath, tcp_conn: TcpConn,
                                  tcp_conn_migrated: TcpConn):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out_port = self.backend_mac_to_port[dpid][tcp_conn_migrated.dst.mac]

        ack = build_tcp(dst=tcp_conn_migrated.dst, src=tcp_conn_migrated.src,
                        seq=tcp_conn.src_isn + 1, ack=tcp_conn_migrated.dst_isn + 1,
                        flags=tcp.TCP_ACK)

        self.send_packet_out(datapath, out_port=out_port, pkt=ack)

        # add flow rules for seq/ack synchronization
        dst_seq_delta = tcp_conn.dst_isn - tcp_conn_migrated.dst_isn
        src_ack_delta = tcp_conn_migrated.dst_isn - tcp_conn.dst_isn

        sync_ack = parser.NXActionIncTcpAck(ack_delta=src_ack_delta) if src_ack_delta > 0 \
            else parser.NXActionDecTcpAck(ack_delta=-src_ack_delta)

        out_port = self.backend_mac_to_port[dpid][tcp_conn_migrated.dst.mac]

        match: OFPMatch = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_src=tcp_conn_migrated.src.ipv4,
                                          ipv4_dst=tcp_conn_migrated.dst.ipv4,
                                          ip_proto=in_proto.IPPROTO_TCP,
                                          tcp_src=tcp_conn_migrated.src.tcp_port,
                                          tcp_dst=tcp_conn_migrated.dst.tcp_port
                                          )

        actions = [sync_ack, parser.OFPActionOutput(port=out_port)]
        self.add_flow(datapath, table_id=0, priority=10, match=match, actions=actions)

        reverse_sync_seq = parser.NXActionIncTcpSeq(seq_delta=dst_seq_delta) if dst_seq_delta > 0 \
            else parser.NXActionDecTcpSeq(seq_delta=-dst_seq_delta)

        reverse_out_port = self.mac_to_port[dpid][tcp_conn_migrated.src.mac]

        reverse_match: OFPMatch = parser.OFPMatch(in_port=2,
                                                  eth_type=ether_types.ETH_TYPE_IP,
                                                  ipv4_src=tcp_conn_migrated.dst.ipv4,
                                                  ipv4_dst=tcp_conn_migrated.src.ipv4,
                                                  ip_proto=in_proto.IPPROTO_TCP,
                                                  tcp_src=tcp_conn_migrated.dst.tcp_port,
                                                  tcp_dst=tcp_conn_migrated.src.tcp_port
                                                  )

        reverse_actions = [reverse_sync_seq, parser.OFPActionOutput(port=reverse_out_port)]
        self.add_flow(datapath, table_id=0, priority=10, match=reverse_match,
                      actions=reverse_actions)

        # send data packet to server 2
        self.send_packet_out(datapath, out_port=out_port, pkt=tcp_conn_migrated.data_pkt)

        # close client-server-1 connection
        self.tcp_reset(datapath, tcp_conn)

        tcp_id = (
            tcp_conn.dst.ipv4, tcp_conn.dst.tcp_port, tcp_conn.src.ipv4, tcp_conn.src.tcp_port)
        del self.tcp_connections[tcp_id]

    def tcp_reset(self, datapath: Datapath, tcp_conn: TcpConn):
        dpid = datapath.id

        out_port = self.mac_to_port[dpid][tcp_conn.dst.mac]

        rst = build_tcp(dst=tcp_conn.dst, src=tcp_conn.src,
                        seq=tcp_conn.src_isn + 1, ack=tcp_conn.dst_isn + 1,
                        flags=tcp.TCP_RST | tcp.TCP_ACK)

        self.send_packet_out(datapath, out_port=out_port, pkt=rst)

    def send_packet_out(self, datapath: Datapath, buffer_id: int = None, in_port: int = None,
                        actions: List[OFPAction] = None, out_port: int = None, pkt=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER
        if in_port is None:
            in_port = ofproto.OFPP_CONTROLLER
        if actions is None:
            actions = [parser.OFPActionOutput(port=out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port,
                                  actions=actions, data=pkt)

        self.logger.info(f'Packet out dpid={datapath.id} in_port={in_port} actions={actions} '
                         f'buffer_id={buffer_id}')
        return datapath.send_msg(out)

    def add_flow(self, datapath: Datapath, table_id: int, priority: int, match: OFPMatch,
                 actions: List[OFPAction], buffer_id: int = None, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=table_id,
                                buffer_id=buffer_id,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                **kwargs)

        self.logger.info(f'Add flow dpid={datapath.id} priority={priority} match={match} '
                         f'actions={actions} buffer_id={buffer_id} {kwargs}')
        return datapath.send_msg(mod)

    def delete_flow(self, datapath: Datapath, priority: int, match: OFPMatch, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                command=ofproto.OFPFC_DELETE,
                                **kwargs)

        self.logger.info(f'Delete flow dpid={datapath.id} priority={priority} match={match} '
                         f'{kwargs}')
        return datapath.send_msg(mod)

    def send_barrier_request(self, datapath: Datapath):
        parser = datapath.ofproto_parser

        req = parser.OFPBarrierRequest(datapath)

        self.logger.info('Barrier request')
        return datapath.send_msg(req)
