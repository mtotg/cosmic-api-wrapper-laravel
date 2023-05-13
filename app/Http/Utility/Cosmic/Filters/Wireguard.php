<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Wireguard extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=80, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Wireguard
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            null,
            Wrapper::$filter_profiles["wireguard"],
            $this->src_ip
        );
        return $this;
    }
}
