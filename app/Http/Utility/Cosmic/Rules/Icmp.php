<?php

namespace App\Http\Utility\Cosmic\Rules;

use App\Http\Utility\Cosmic\Wrapper;

class Icmp extends \App\Http\Utility\Cosmic\Rule
{
    public function __construct(public string|int $action="drop")
    {
        parent::__construct();
    }

    public function setup(): Icmp
    {
        $tcp_rule = (object) array(
            'dst_port' => '0',
            'protocol' => Wrapper::$protocols["icmp"],
            'rule' => Wrapper::mapAction($this->action)
        );
        $this->my_rule_tree[] = $tcp_rule;
        return $this;
    }
}
