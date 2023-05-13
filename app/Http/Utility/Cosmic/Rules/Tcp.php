<?php

namespace App\Http\Utility\Cosmic\Rules;

use App\Http\Utility\Cosmic\Wrapper;

class Tcp extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $tcp_port=80, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Tcp
    {
        if($this->tcp_port == 0 && Wrapper::mapAction($this->action) == 1) {
            $tcp_rule = (object) array(
                'dst_port' => '0',
                'protocol' => "tcp",
                'rule' => Wrapper::mapAction($this->action)
            );
            if($this->src_ip != null && $this->src_ip != "0") {
                $tcp_rule->src_ip = $this->src_ip;
            }
            $this->my_rule_tree[] = $tcp_rule;
        }
        else {
            $this->addProtocolFilterRule(
                null,
                $this->tcp_port,
                Wrapper::mapAction($this->action),
                $this->src_ip
            );
        }
        return $this;
    }
}
