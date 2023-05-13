<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Samp extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $tcp_port = 27015, public int $udp_port=27015, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Samp
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            $this->tcp_port,
            Wrapper::$filter_profiles["samp"],
            $this->src_ip
        );
        return $this;
    }
}
