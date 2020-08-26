<?php

namespace qingxiaoyun\auth;

use BcryptHasher;
use Brooke\Policy\UserContract;

class EloquentUserProvider
{
    /**
     * BcryptHasher Instance.
     */
    protected $hasher;

    /**
     * The Eloquent user model.
     *
     * @var string
     */
    protected $model;

    /**
     * Create a new database user provider.
     *
     * @param  BcryptHasher Instance  $hasher
     * @param  string  $model
     * @return void
     */
    public function __construct($model, BcryptHasher $hasher)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }

    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);
        $user->save();
    }

    public function retrieveById($identifier)
    {
        $model = $this->createModel();

        return $model->newQuery()
            ->where($model->getAuthIdentifierName(), $identifier)
            ->find();
    }

    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();

        $model = $model->where($model->getAuthIdentifierName(), $identifier)->find();

        if (! $model) {
            return;
        }

        $rememberToken = $model->getRememberToken();

        return $rememberToken && hash_equals($rememberToken, $token) ? $model : null;
    }

    public function createModel()
    {
        $class = '\\'.ltrim($this->model, '\\');

        return new $class;
    }
}
