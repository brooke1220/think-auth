<?php
namespace qingxiaoyun\auth;

use think\App;
use think\Request;
use qingxiaoyun\auth\EloquentUserProvider;
use qingxiaoyun\auth\SessionGuard;
use Brooke\Supports\ServiceProvider;

class AuthProvider extends ServiceProvider
{
    protected $name = 'qingxiaoyun';

    protected $model = \app\common\model\Users::class;

    public static function register(App $app, Request $request)
	  {
        $instance = static::getInstance();

        $app->bindTo(EloquentUserProvider::class, function() use ($app, $instance){
            return $app->invokeClass(EloquentUserProvider::class, [ $instance->model ]);
        });

        $app->bindTo(SessionGuard::class, function() use ($app, $instance){
            return $app->invokeClass(SessionGuard::class, [ $instance->name ]);
        });
	  }
}
