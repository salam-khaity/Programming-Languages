<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


Route::post('login', [AuthController::class,'login']);
Route::post('register', [AuthController::class,'register']);
Route::group(['middleware'=>['auth:api']], function (){
    Route::post('logout', [AuthController::class,'logout']);
});
