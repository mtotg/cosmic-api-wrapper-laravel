<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Openvpn extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=22701, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Openvpn
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            null,
            Wrapper::$filter_profiles["openvpn"],
            $this->src_ip
        );
        return $this;
    }
}
