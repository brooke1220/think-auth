<?php

namespace qingxiaoyun\auth;

trait Authenticatable
{
    protected $rememberTokenName = 'remember_token';

    public function setRememberToken($value)
    {
        if (! empty($this->getRememberTokenName())) {
            $this->{$this->getRememberTokenName()} = $value;
        }
    }

    public function getAuthPassword()
    {
        return $this->password;
    }

    public function getRememberToken()
    {
        if (! empty($this->getRememberTokenName())) {
            return (string) $this->{$this->getRememberTokenName()};
        }
    }

    public function getRememberTokenName()
    {
        return $this->rememberTokenName;
    }
}
