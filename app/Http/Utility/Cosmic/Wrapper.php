<?php

namespace App\Http\Utility\Cosmic;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

class Wrapper
{
    public static $RULE_DROP = 1;
    public static $RULE_PASS = 2;
    /**
     * To drop all, specify dst_port as 0
     */

    public static function mapAction(string|int $action): int
    {
        if(is_string($action)) {
            $action = strtolower($action);
            if($action == "drop") return self::$RULE_DROP;
            if($action == "1") return self::$RULE_DROP;
            return self::$RULE_PASS;
        }
        return $action; // if its an int already, pass-through it
    }

    // Variable Declarations
    public string $api_url = "https://cosmic.global/apiexp/v1";

    /**
     * @var array|int[] Profile Map
     */
    public static array $filter_profiles = array(
        "fivem" => 4,
        "raknet" => 5,
        "ddnet" => 6,
        "samp" => 7,
        "steamnet" => 8,
        "hurtworld" => 9,
        "scp" => 10,
        "gmod" => 11,
        "raknetv2" => 14,
        "wireguard" => 16,
        "dayz" => 18,
        "openvpn" => 19,
        "csgo" => 21,
    );

    /**
     * @var array|int[] Protocol Map
     */
    public static array $protocols = array(
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
    );

    private array $staged_rules = array();

    public function __construct(public $api_key = "") {}

    public function listRules($ip_address) {
        $client = new Client();
        $res = $client->request('GET',$this->api_url . "/rules/" . $ip_address, ['headers' => ['X-Access-Token' => $this->api_key]]);
        $body = $res->getBody();
        return json_decode($body);
    }

    public function listRulesSubnet($ip_subnet) {}

    /**
     * @param Rule $rule
     * @return void
     *
     * curl -H "Content-Type: application/json" -H "X-Access-Token: YOURKEY" -d '[{ "dst_port": "22", "protocol": "tcp", "rule": "drop" }]' --request "PATCH" https://cosmic.global/apiexp/v1/rules/13.37.13.37
     */
    public function stageNewRule($rule): Wrapper {
        $my_rules = $this->staged_rules;
        $the_requested_rules = $rule->array();
        $merged = array_merge($my_rules, $the_requested_rules);
        $this->staged_rules = $merged;
        return $this;
    }

    public function previewCommit()
    {
        return json_encode($this->staged_rules);
    }

    private static function flipProtocolBit(string|int $bit, $invert = false): string
    {
        if(!is_int($bit)) return $bit; // exit early
        // PROTO MAP!
        if(!$invert) {
            return match ($bit) {
                "2" => "tcp",
                "17" => "udp",
                "47" => "gre",
                default => "icmp"
            };
        }
        return match ($bit) {
            "tcp" => "2",
            "udp" => "17",
            "grep" => "47",
            default => "icmp"
        };
    }

    private static function flipRuleBit(string|int $bit): string
    {
        if(!is_int($bit)) return $bit;
        $bit = (string) $bit;
        error_log($bit);
        // PROFILE MAP!
        $result = match($bit) {
            "2" => "pass",
            "4" => "fivem",
            "5" => "raknet",
            "6" => "ddnet",
            "7" => "samp",
            "8" => "steamnet",
            "9" => "hurtworld",
            "10" => "scp",
            "11" => "gmod",
            default => "drop"
        };
        return $result;
    }

    public function insertRules($ip_address, $flip_proto_bits = false)
    {
        $bits = $this->staged_rules;
        if($flip_proto_bits) {
            foreach($bits as &$bit)
            {
                /**
                 * ["dst_port", "protocol", "rule"]
                 */
                $bit->protocol = self::flipProtocolBit($bit->protocol);
                $bit->rule = self::flipRuleBit($bit->rule);
            }
            $bits = $this->staged_rules;
        }
        $bits = json_encode($bits);
        error_log("Applying Rules: " . $bits);
//        return; // don't apply them again
        $client = new Client();
        $res = $client->request('POST',$this->api_url . "/rules/" . $ip_address, ['headers' => ['Content-Type' => 'application/json', 'X-Access-Token' => $this->api_key], 'body' => $bits]);
        return json_decode($res->getBody());
    }

    public function upsertRules($ip_address, $flip_proto_bits = false) {
        $bits = $this->staged_rules;
        if($flip_proto_bits) {
            foreach($bits as &$bit)
            {
                /**
                 * ["dst_port", "protocol", "rule"]
                 */
                $bit->protocol = self::flipProtocolBit($bit->protocol);
                $bit->rule = self::flipRuleBit($bit->rule);
                $bit->dst_port = (string) $bit->dst_port;
            }
            $bits = $this->staged_rules;
        }
        Log::info("Staged Rules: " . json_encode($bits));
        $responses = [];
        // ITER NOW
        foreach($bits as $rule)
        {
            // now we have the actual rule array
            $client = new Client();
            $body = json_encode([$rule]);
            Log::info('PATCH body ' . $body);
            $res = $client->request('PATCH', $this->api_url . "/rules/" . $ip_address, ['headers' => [
                'Content-Type' => 'application/json',
                'X-Access-Token' => $this->api_key,
            ], 'body' => $body]);
            $responses[] = json_decode($res->getBody());
        }
        return $responses;
    }

    public function deleteRule($ip_address, $port, $proto, $flip_proto_bits = false, $src_ip = null)
    {
        if($flip_proto_bits) {
            $proto = self::flipProtocolBit($proto, true);
        }
        if(env('APP_ENV') == "local") Log::info("deleteRule: " . $ip_address . " / " . $port . " / " . $proto);
        $path = $this->api_url . "/rules/" . $ip_address . "/" . $port . "/" . strtolower($this->protocol($proto));
        if($src_ip != "0") {
            $path .= "/" . $src_ip;
        }
        if(env('APP_ENV') == "local") Log::info("Deletion Path: " . $path);
        $headers = ['headers' => [
                'Content-Type' => 'application/json',
                'X-Access-Token' => $this->api_key,
            ]
        ];
        if(env('APP_ENV') == "local") Log::info("deleteRule " . $path);
        $client = new Client();
        try {
            $res = $client->request('DELETE', $path, $headers);
            return $res->getBody();
        } catch(\Exception $ex) {
            error_log($ex->getMessage());
            return true;
        }
    }

    public function execRaw($ip_address, $raw_json)
    {
        $path = $this->api_url . "/rules/" . $ip_address;
        $headers = ['headers' => [
                'Content-Type' => 'application/json',
                'X-Access-Token' => $this->api_key,
            ],
            'body' => $raw_json
        ];
        $client = new Client();
        try {
            $res = $client->request('POST', $path, $headers);
            return $res->getBody();
        } catch(\Exception $ex) {
            error_log($ex->getMessage());
            return true;
        }
    }

    public function deleteAllRules($ip_address)
    {
        $client = new Client();
        $res = $client->request('DELETE',$this->api_url . "/rules/" . $ip_address, ['headers' => ['Content-Type' => 'application/json', 'X-Access-Token' => $this->api_key], 'http_errors' => false]);
        return $res->getBody();
    }

    /**
     * THIS IS A SIMPLE CONVERSION LOGIC
     */
    public function protocol($proto_id): string {
        $proto_id = (string) $proto_id;
        return match($proto_id) {
            "6" => "TCP",
            "17" => "UDP",
            "47" => "GRE",
            "udp" => "UDP",
            "tcp" => "TCP",
            "gre" => "GRE",
            default => "ICMP"
        };
    }
    public function rule($rule_id): string {
        $rule_id = (string) $rule_id;
        return match($rule_id) {
            "2" => "Pass",
            "4" => "FiveM",
            "5" => "RAKNET",
            "6" => "DDNET",
            "7" => "SAMP",
            "8" => "STEAMNET",
            "9" => "HURTWORLD",
            "10" => "SCP",
            "11" => "GMOD",
            "16" => "WIREGUARD",
            "fivem" => "FiveM",
            "raknet" => "RAKNET",
            "raknetv2" => "RAKNETV2",
            "ddnet" => "DDNET",
            "samp" => "SAMP",
            "steamnet" => "STEAMNET",
            "hurtworld" => "HURTWORLD",
            "scp" => "SCP",
            "gmod" => "GMOD",
            "wireguard" => "WIREGUARD",
            "pass" => "Pass",
            "drop" => "Drop",
            default => "Drop"
        };
    }
}
