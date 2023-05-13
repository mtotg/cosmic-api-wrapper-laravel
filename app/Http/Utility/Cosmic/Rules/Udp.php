<?php

namespace App\Http\Utility\Cosmic\Rules;

use App\Http\Utility\Cosmic\Wrapper;

class Udp extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=80, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Udp
    {
        if($this->udp_port == 0 && Wrapper::mapAction($this->action) == 1) {
            $udp_rule = (object) array(
                'dst_port' => '0',
                'protocol' => "udp",
                'rule' => Wrapper::mapAction($this->action)
            );
            if($this->src_ip != null && $this->src_ip != "0") {
                $udp_rule->src_ip = $this->src_ip;
            }
            $this->my_rule_tree[] = $udp_rule;
        }
        else {
            $this->addProtocolFilterRule(
                $this->udp_port,
                null,
                Wrapper::mapAction($this->action),
                $this->src_ip
            );
        }
        return $this;
    }
}
