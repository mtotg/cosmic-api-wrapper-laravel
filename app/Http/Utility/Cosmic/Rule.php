<?php

namespace App\Http\Utility\Cosmic;

class Rule
{
    public array $my_rule_tree = array();

    public function __construct() {
        $this->setup();
    }

    public function addProtocolFilterRule($udp_port = null, $tcp_port = null, $filter = null, $src_ip = null): Rule {
        if($udp_port != null) {
            $udp_rule = (object) array(
                'dst_port' => $udp_port,
                'protocol' => 'udp',
                'rule' => $filter
            );
            if($src_ip != null && $src_ip != "0") {
                $udp_rule->src_ip = $src_ip;
            }
            $this->my_rule_tree[] = $udp_rule;
        }
        if($tcp_port != null) {
            $tcp_rule = (object) array(
                'dst_port' => $tcp_port,
                'protocol' => 'tcp',
                'rule' => $filter
            );
            if($src_ip != null && $src_ip != "0") {
                $tcp_rule->src_ip = $src_ip;
            }
            $this->my_rule_tree[] = $tcp_rule;
        }
        return $this;
    }

    public function array() {
        return $this->my_rule_tree;
    }
    public function setup(): mixed {}
}
