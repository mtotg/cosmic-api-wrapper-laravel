<?php

namespace App\Http\Utility\Cosmic\Filters;
use App\Http\Utility\Cosmic\Wrapper;

class Rust extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public int $udp_port=28015, public int $tcp_port=28015)
    {
        parent::__construct();
    }

    public function setup(): Rust
    {
        $this->addProtocolFilterRule(
            $this->udp_port,
            $this->tcp_port,
            Wrapper::$filter_profiles["raknet"]
        );
        return $this;
    }
}
