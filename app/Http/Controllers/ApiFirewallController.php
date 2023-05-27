<?php

namespace App\Http\Controllers;

use App\Http\Utility\Cosmic\Filters\Csgo;
use App\Http\Utility\Cosmic\Filters\Dayz;
use App\Http\Utility\Cosmic\Filters\Fivem;
use App\Http\Utility\Cosmic\Filters\Openvpn;
use App\Http\Utility\Cosmic\Filters\Scp;
use App\Http\Utility\Cosmic\Filters\Wireguard;
use App\Http\Utility\Cosmic\Rules\Icmp;
use App\Http\Utility\Cosmic\Rules\Tcp;
use App\Http\Utility\Cosmic\Rules\Udp;
use App\Http\Utility\Cosmic\Wrapper;
use App\Models\FirewallLocking;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use App\Http\Utility\Cosmic\Filters\Raknet;
use App\Http\Utility\Cosmic\Filters\Gmod;
use App\Http\Utility\Cosmic\Filters\Samp;
use App\Http\Utility\Cosmic\Filters\Ddnet;
use Illuminate\Support\Facades\Redis;

class ApiFirewallController extends Controller
{
    private static string $API_KEY = "";
    private static $api_key_to_ips_map = array(
	'exampleKEYgoesHERE123' => '1.1.1.2-1.1.1.5;9.69.9.69-10.69.10.69',
    );

    private function authorized($ip_address, $api_key): bool
    {
        $map = self::$api_key_to_ips_map;
        if(isset($map[$api_key])) {
            // we have an API key that matches, let's just filter on the IP address
            $ranges = array();
            if(stristr($map[$api_key], ";")) {
                $split_pieces = explode(';', $map[$api_key]);
                foreach($split_pieces as $piece) {
                    $ranges[] = $piece;
                }
            }
            else {
                $ranges[] = $map[$api_key];
            }
            foreach($ranges as $range)
            {
                $map_split = explode("-", $range);
                $first_starter = explode(".", $map_split[0])[3]; // first digit of the last octet of the IP... e.g., 207.174.40.1
                $last_finisher = explode(".", $map_split[1])[3]; // last digit of the last octet of the IP... e.g., 207.174.40.128
                $authorized_ips = array();
                $exploder = explode(".", $map_split[0]);
                for($i = $first_starter; $i < $last_finisher+1; $i++)
                {
                    // rebuild array
                    $digits = $exploder[0] . "." . $exploder[1] . "." . $exploder[2] . "." . $i;
                    $authorized_ips[] = $digits;
                }
                if(in_array($ip_address, $authorized_ips)) return true;
            }
        }
        return false;
    }

    public function preset_list(Request $request)
    {
        return json_encode(
            array(
                '1' => 'cpanel',
                '2' => 'directadmin',
                '3' => 'general-http-server',
                '4' => 'windows-rdp',
                '5' => 'special-fivem-experimental'
            )
        );
    }

    public function preset(Request $request, $ip_address, $preset_id)
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        if($this->isLocked($ip_address)) abort(403);
        $wrapper = new Wrapper(self::$API_KEY);
        $wrapper->deleteAllRules($ip_address);
        // Some generic rules
        $ssh = new Tcp(22, "pass");
        $smtp = new Tcp(25, "pass");
        $smtp_alt = new Tcp(26, "pass");
        $dns = new Tcp(53, "pass");
        $dns_udp = new Udp(53, "pass");
        $http = new Tcp(80, "pass");
        $https = new Tcp(443, "pass");
        $pop3 = new Tcp(110, "pass");
        $imap = new Tcp(143, "pass");
        $smtps = new Tcp(465, "pass");
        $exim = new Tcp(587, "pass");
        $mysql = new Tcp(3306, "pass");
        $imaps = new Tcp(993, "pass");
        $pop3s = new Tcp(995, "pass");
        $icmp_drop = new Icmp("drop");
        $tcp_drop = new Tcp(0, "drop");
        $udp_drop = new Udp(0, "drop");
        // Now wrap the presets here
        if($preset_id == '1')
        {
            // cPanel / WHM Server
            // Generics first!
            $wrapper->stageNewRule($ssh)
                ->stageNewRule($smtp)
                ->stageNewRule($smtp_alt)
                ->stageNewRule($dns)
                ->stageNewRule($dns_udp)
                ->stageNewRule($http)
                ->stageNewRule($https)
                ->stageNewRule($pop3)
                ->stageNewRule($imap)
                ->stageNewRule($smtps)
                ->stageNewRule($exim)
                ->stageNewRule($mysql)
                ->stageNewRule($imaps)
                ->stageNewRule($pop3s);
            // Custom for cPanel
            $caldev_one = new Tcp(2079, "pass");
            $caldev_two = new Tcp(2080, "pass");
            $cpanel_one = new Tcp(2082, "pass");
            $cpanel_two = new Tcp(2083, "pass");
            $whm_one = new Tcp(2086, "pass");
            $whm_two = new Tcp(2087, "pass");
            $webmail = new Tcp(2095, "pass");
            $webmail_two = new Tcp(2096, "pass");
            // Add our custom rules
            $wrapper->stageNewRule($caldev_one)
                ->stageNewRule($caldev_two)
                ->stageNewRule($cpanel_one)
                ->stageNewRule($cpanel_two)
                ->stageNewRule($whm_one)
                ->stageNewRule($whm_two)
                ->stageNewRule($webmail)
                ->stageNewRule($webmail_two);
            // Now do the drop all
            $wrapper->stageNewRule($icmp_drop)
                ->stageNewRule($tcp_drop)
                ->stageNewRule($udp_drop);
            // Now persist!
            $wrapper->upsertRules($ip_address, true);
        }
        if($preset_id == '2')
        {
            $wrapper->stageNewRule($ssh)
                ->stageNewRule($exim)
                ->stageNewRule($smtp)
                ->stageNewRule($dns)
                ->stageNewRule($dns_udp)
                ->stageNewRule($http)
                ->stageNewRule($https)
                ->stageNewRule($mysql)
                ->stageNewRule(new Tcp(110, "pass"))
                ->stageNewRule(new Tcp(143, "pass"))
                ->stageNewRule(new Tcp(993, "pass"))
                ->stageNewRule(new Tcp(995, "pass"))
                ->stageNewRule(new Tcp(2222, "pass"))
                ->stageNewRule($icmp_drop)
                ->stageNewRule($tcp_drop)
                ->stageNewRule($udp_drop)
                ->upsertRules($ip_address, true);
        }
        if($preset_id == '3')
        {
            $wrapper->stageNewRule($ssh)
                ->stageNewRule($http)
                ->stageNewRule($https)
                ->stageNewRule($icmp_drop)
                ->stageNewRule($tcp_drop)
                ->stageNewRule($udp_drop)
                ->upsertRules($ip_address, true);
        }
        if($preset_id == '4')
        {
            $wrapper->stageNewRule(new Tcp(3389, "pass"))
                ->stageNewRule($icmp_drop)
                ->stageNewRule($tcp_drop)
                ->stageNewRule($udp_drop)
                ->upsertRules($ip_address, true);
        }
        return json_encode(array('state' => 'ok'));
    }

    public function list(Request $request, $ip_address)
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        $wrapper = new Wrapper(self::$API_KEY);
        return json_encode($wrapper->listRules($ip_address));
    }

    private function isLocked(string $ip_address): bool
    {
        $lock_query = FirewallLocking::query()->where('ipv4_address', '=', $ip_address)->first();
        if($lock_query) {
            return $lock_query->locked;
        }
        return false;
    }

    private function toggleLock(string $ip_address): void
    {
        $lock_query = FirewallLocking::query()->where('ipv4_address', '=', $ip_address)->first();
        if($lock_query) {
            $lock_query->locked = !$lock_query->locked;
            $lock_query->save();
            return;
        }
        $lock_query = new FirewallLocking();
        $lock_query->ipv4_address = $ip_address;
        $lock_query->locked = true;
        $lock_query->save();
    }

    public function lock(Request $request, string $ip_address)
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        $this->toggleLock($ip_address);
        return json_encode(['state' => 'ok']);
    }

    public function add(Request $request, $ip_address, $udp_port = 0, $tcp_port = 0, $protocol = "tcp", $mode = "pass", $src_ip = null) // default pass
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        if($this->isLocked($ip_address)) abort(403);
        $wrapper = new Wrapper(self::$API_KEY);
        if($protocol == Wrapper::$protocols["icmp"]) {
            $rule = new Icmp($mode);
            $wrapper->stageNewRule($rule);
            $wrapper->upsertRules($ip_address, true); // flip bits always to be true, for simplicity
            return json_encode(['state' => 'ok']);
        }
        // otherwise, let's just make the rule
        if($mode == "fivem") {
            // this is a FiveM server, let's address it
            $fivem = new Fivem($udp_port, $tcp_port);
            if($request->get('experimental', false)) {
                $fivem->flag('experimental', $request->get('experimental', false));
            }
            $wrapper->stageNewRule($fivem);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "wireguard") {
            // WIREGUARD
            $wireguard = new Wireguard($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($wireguard);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "raknet") {
            // RAKNET
            $raknet = new Raknet($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($raknet);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "raknetv2") {
            // RAKNET
            $raknet = new Raknet($udp_port, $mode, $src_ip, "v2");
            $wrapper->stageNewRule($raknet);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "scp") {
            // SCP:SL
            $scp = new Scp($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($scp);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "gmod") {
            // GMOD
            $gmod = new Gmod($tcp_port, $udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($gmod);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "samp") {
            // SA-MP
            $samp = new Samp($tcp_port, $udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($samp);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "ddnet") {
            // DDNET
            $ddnet = new Ddnet($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($ddnet);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "dayz") {
            // DAYZ
            $dayz = new Dayz($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($dayz);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "openvpn") {
            // OPENVPN
            $openvpn = new Openvpn($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($openvpn);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        } elseif($mode == "csgo") {
            // CSGO
            $csgo = new Csgo($udp_port, $mode, $src_ip);
            $wrapper->stageNewRule($csgo);
            $wrapper->upsertRules($ip_address, true);
            return json_encode(['state' => 'ok']);
        }
        else {
            if($protocol == "udp") {
                $udp = new Udp($udp_port, $mode, $src_ip);
                $wrapper->stageNewRule($udp);
                $wrapper->upsertRules($ip_address, true);
            } elseif($protocol == "tcp") {
                $tcp = new Tcp($tcp_port, $mode, $src_ip);
                $wrapper->stageNewRule($tcp);
                $wrapper->upsertRules($ip_address, true);
            } elseif($protocol == "icmp") {
                $icmp = new Icmp($mode);
                $wrapper->stageNewRule($icmp);
                $wrapper->upsertRules($ip_address, true);
            }
            return json_encode(['state' => 'ok']);
        }
        return json_encode(['state' => 'unsupported']);
    }

    public function remove(Request $request, $ip_address, $udp_port = 0, $tcp_port = 0, $protocol = "tcp", $mode = "pass", $src_ip = null) // default pass
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        if($this->isLocked($ip_address)) abort(403);
        $wrapper = new Wrapper(self::$API_KEY);
        if($udp_port != 0) {
            $wrapper->deleteRule($ip_address, $udp_port, $protocol, false, $src_ip);
            return json_encode(['state' => 'ok']);
        }
        elseif($tcp_port != 0) {
            $wrapper->deleteRule($ip_address, $tcp_port, $protocol, false, $src_ip);
            return json_encode(['state' => 'ok']);
        }
        elseif($tcp_port == 0 || $udp_port == 0) {
            $wrapper->deleteRule($ip_address, 0, $protocol, false, $src_ip);
            return json_encode(['state' => 'ok']);
        }
        if($protocol == "icmp" || $protocol == "1") {
            // icmp
            $wrapper->deleteRule($ip_address, 0, "icmp", false, $src_ip);
            return json_encode(['state' => 'ok', 'meta' => ['icmp' => 'changed']]);
        }
        return json_encode(['state' => 'unsupported']);
    }

    public function raw(Request $request, $ip_address)
    {
        $api_key = $request->header('X-Auth-Token');
        if(!$this->authorized($ip_address, $api_key)) abort(403);
        if($this->isLocked($ip_address)) abort(403);
        $wrapper = new Wrapper(self::$API_KEY);
        return $wrapper->execRaw($ip_address, $request->get('raw_input'));
    }
}

