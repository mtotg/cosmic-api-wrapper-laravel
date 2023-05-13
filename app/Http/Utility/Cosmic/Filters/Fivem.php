<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Fivem extends \App\Http\Utility\Cosmic\Rule
{
    /**
     * '[{ "dst_port": "30120", "protocol": "udp", "rule": "fivem" },{ "dst_port": "30120", "protocol": "tcp", "rule": "fivem"},{ "dst_port": "0", "protocol": "udp", "rule": "drop" }]'
     */

    public function __construct(public int $udp_port=30120, public int $tcp_port=30120)
    {
        parent::__construct();
    }

    public function setup(): Fivem
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            $this->tcp_port,
            Wrapper::$filter_profiles["fivem"]
        );
        return $this;
    }
}
