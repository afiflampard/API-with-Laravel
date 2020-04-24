<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function signup(Request $request){

        $this->validate($request,[
            'username' => 'required|unique:users',
            'email' => 'required|unique:users',
            'password'=>'required',
            'nama' =>'required',
            'No_WA'=>'required'
        ]);
       return User::create([
            'username' => $request->json('username'),
            'email' => $request->json('email'),
            'password'=> bcrypt($request->json('password')),
            'nama' => $request->json('nama'),
            'No_WA'=> $request->json('No_WA'),
       ]); 
    }
    public function signin(Request $request){

        $this->validate($request,[
            'username' => 'required', 'password'=>'required',
        ]);

        $credentials = $request->only('username', 'password');

        try {
            // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        // all good so return the token
        return response()->json([
            'user_id' => $request->user()->id,
            'token' => $token
        ]);
    }
    public function forgotPassword(Request $request){
        $this->validate($request,[
            'email' => 'required', 'password' =>'required'
        ]);
        $for = User::where('email',$request->email)->first();
        $for->password = bcrypt($request->password);
        $for->save();

        return $for;
    }

}
