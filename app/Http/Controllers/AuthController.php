<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request){
        $request->validate([
            'name'=> 'required|string|max:55',
            'phone'=>'required|regex:/[0-9]{10}/|digits:10|numeric',
            'password'=> 'required|confirmed|min:8',
        ]);

        $user = User::query()->create([
            'name' => $request->name ,
            'phone' => $request->phone ,
            'password' => bcrypt($request->password) ,
        ]);
        if (!$user){
            return response()->json([
                'success' => false,
                'message'=> 'Registration Failed'
            ]);
        }
        $accessToken = $user->createToken('MyApp')->accessToken;
        $user['remember_token']=$accessToken;
        return response([
           'user'=>$user,
           'access_token'=>$accessToken
        ]);
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'phone' => 'required|exists:users|regex:/[0-9]{10}/|digits:10|numeric',
            'password'=>'required|string'
        ]);
        if (!auth()->attempt($loginData)){
            return response()->json(['message' => 'Invalid credentials'], 422);
        }
        $user = $request->user();
        $accessToken = $user->createToken('MyApp');
        $user['remember_token'] = $accessToken;
        $accessToken->token->save();
            return response()->json([
                'data' => $user,
                'access_token'=>$accessToken->accessToken,
            ]);
    }

    public function logout(){
        Auth::user()->token()->revoke();
        return response()->json(['success'=>'Logged Out Successfully'], 200);
    }

}
