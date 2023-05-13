<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Raknet extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=80, public string|int $action="drop", public null|string|int $src_ip = 0, public string $extra = "")
    {
        parent::__construct();
    }

    public function setup(): Raknet
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            null,
            Wrapper::$filter_profiles["raknet". $this->extra],
            $this->src_ip
        );
        return $this;
    }
}
