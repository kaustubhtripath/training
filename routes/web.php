<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

/*
$router->get('/', function () use ($router) {
    return $router->app->version();
});
*/ //uncommented from jwt tutorial


$router->get('/', function () use ($router) {
    echo "<center> Welcome </center>";
});

$router->get('/version', function () use ($router) {
    return $router->app->version();
});

Route::group([

    //'prefix' => 'api', //uncommented by seeing the jwt tutorial without seeder
    'prefix' => 'auth', //added this seeing the previous tutorial
    'middleware' => 'api',
    

], function ($router) {
    Route::post('login', 'AuthController@login');
    Route::post('logout', 'AuthController@logout');
    Route::post('refresh', 'AuthController@refresh');
    Route::post('user-profile', 'AuthController@me');

});
// from the jwt token tutorial

$router->post('/password/reset-request', 'RequestPasswordController@sendResetLinkEmail');
$router->post('/password/reset', [ 'as' => 'password.reset', 'uses' => 'ResetPasswordController@reset' ]);


/*
$router->group(['prefix' => 'api'], function () use ($router) {
    
});
    /*
    $router->get('authors',  ['uses' => 'AuthorController@showAllAuthors']);
  
    $router->get('authors/{id}', ['uses' => 'AuthorController@showOneAuthor']);
  
    $router->post('authors', ['uses' => 'AuthorController@create']);
  
    $router->delete('authors/{id}', ['uses' => 'AuthorController@delete']);
  
    $router->put('authors/{id}', ['uses' => 'AuthorController@update']);
  });
  */   // from the author tutorial 1st one 

  // for email verification


  
  //Route::get('products', ['middleware' => 'auth.role:admin,user', 'uses' => 'ProductController@index', 'as' => 'products']);

 
  $router->get('/users',['middleware'=>'auth.role:admin,user', 'uses' =>'AuthController@showAllUsers'] );
  $router->post('/user', 'AuthController@create');



  
  $router->group(['middleware' => ['auth', 'verified']], function () use ($router) {
    $router->post('/logout', 'AuthController@logout');
    $router->get('/user', 'AuthController@user');
    $router->post('/email/request-verification', ['as' => 'email.request.verification', 'uses' => 'AuthController@emailRequestVerification']);
    $router->post('/refresh', 'AuthController@refresh');
    $router->post('/deactivate', 'AuthController@deactivate');
  });



  $router->post('/password/email', 'PasswordController@postEmail');
  $router->post('/register', 'AuthController@register');
  $router->post('/login', 'AuthController@login');
  $router->post('/reactivate', 'AuthController@reactivate');
  $router->post('/password/reset-request', 'RequestPasswordController@sendResetLinkEmail');
  $router->post('/password/reset', [ 'as' => 'password.reset', 'uses' => 'ResetPasswordController@reset' ]);
  $router->post('/email/verify', ['as' => 'email.verify', 'uses' => 'AuthController@emailVerify']);
