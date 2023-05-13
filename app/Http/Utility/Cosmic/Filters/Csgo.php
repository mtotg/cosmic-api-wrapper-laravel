<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Csgo extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=27015, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Csgo
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            null,
            Wrapper::$filter_profiles["csgo"],
            $this->src_ip
        );
        return $this;
    }
}
