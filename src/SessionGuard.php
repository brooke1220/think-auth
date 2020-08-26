<?php

namespace qingxiaoyun\auth;

use think\Session;
use think\Request;
use Brooke\Traits\Macroable;
use Brooke\Policy\UserContract;

class SessionGuard
{
    use Macroable;

    /**
    * The session used by the guard.
    *
    * @var \think\Session
    */
    protected $session;

    /**
     * The request instance.
     *
     * @var \think\Request
     */
    protected $request;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * Indicates if the user was authenticated via a recaller cookie.
     *
     * @var bool
     */
    protected $viaRemember = false;

    /**
     * Indicates if a token user retrieval has been attempted.
     *
     * @var bool
     */
    protected $recallAttempted = false;

    /*
     * Cookie expiration time
     */
    protected $rememberCookieExpire = 259200;

    /**
     * Create a new authentication guard.
     *
     * @param  string  $name
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \think\Session  $session
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     * @return void
     */
    public function __construct(string $name,
                                EloquentUserProvider $provider,
                                Session $session,
                                Request $request)
    {
        $this->name = $name;
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
    }

    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        
        if (! empty($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        if (! is_null($id)) {
             $this->user = $this->provider->retrieveById($id);
        }

        $this->user = null;

        $recaller = $this->recaller();

        if (is_null($this->user) && ! is_null($recaller)) {
            $this->user = $this->userFromRecaller($recaller);

            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());
            }
        }

        return $this->user;
    }

    protected function userFromRecaller($recaller)
    {
        if (! $recaller->valid() || $this->recallAttempted) {
            return;
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $this->recallAttempted = true;

        $this->viaRemember = ! is_null($user = $this->provider->retrieveByToken(
            $recaller->id(), $recaller->token()
        ));

        return $user;
    }

    protected function recaller()
    {
        if (is_null($this->request)) {
            return;
        }

        if ($recaller = $this->request->cookie($this->getRecallerName())) {
            return new Recaller($recaller);
        }
    }

    public function login(UserContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());

        if ($remember) {
            $this->ensureRememberTokenIsSet($user);

            $this->recallerCookie($user);
        }

        $this->setUser($user);
    }

    protected function cycleRememberToken(UserContract $user)
    {
        $user->setRememberToken($token = \Str::quickRandom(60));

        $this->provider->updateRememberToken($user, $token);
    }

    public function recallerCookie(UserContract $user)
    {
        $value = $user->getAuthIdentifier().'|'.$user->getRememberToken().'|'.$user->getAuthPassword();

        $this->rememberCookieExpire ?
          $this->getCookieJar()->set($this->getRecallerName(), $value, ['expire' => $this->rememberCookieExpire]) :
          $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }

    public function setUser(UserContract $user)
    {
        $this->user = $user;

        $this->loggedOut = false;

        return $this;
    }

    protected function ensureRememberTokenIsSet(UserContract $user)
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    public function logout()
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        if (! is_null($this->user)) {
            $this->cycleRememberToken($user);
        }

        $this->user = null;

        $this->loggedOut = true;
    }

    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());

        if (! is_null($this->recaller())) {
            $this->getCookieJar()->queue($this->getCookieJar()
                    ->forget($this->getRecallerName()));
        }
    }

    public function getName()
    {
        return 'login_'.$this->name.'_'.sha1(static::class);
    }

    public function getRecallerName()
    {
        return 'remember_'.$this->name.'_'.sha1(static::class);
    }

    public function getCookieJar()
    {
        if (! isset($this->cookie)) {
            $this->cookie = app()->make('cookie');
        }

        return $this->cookie;
    }

    public function updateSession($id)
    {
        $this->session->set($this->getName(), $id);
    }
}
