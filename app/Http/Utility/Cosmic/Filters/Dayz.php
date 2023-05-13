<?php

namespace App\Http\Utility\Cosmic\Filters;

use App\Http\Utility\Cosmic\Wrapper;

class Dayz extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=2302, public string|int $action="drop", public null|string|int $src_ip = 0)
    {
        parent::__construct();
    }

    public function setup(): Dayz
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            null,
            Wrapper::$filter_profiles["dayz"],
            $this->src_ip
        );
        return $this;
    }
}
