<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function register(Request $request) {
        // echo "<pre>";
        // print_r($request->all());

        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'min:8', 'confirmed'],
            'password_confirmation' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $validatedData = $validator->validated();
        $validatedData['password'] = Hash::make($validatedData['password']);
        
        $user = User::create($validatedData);

        $token = $user->createToken('auth_token')->accessToken;

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token,
            'status' => 1
        ], 201);

    }

    public function login(Request $request) {

        $validator = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $validatedData = $validator->validated();
        
        $user = User::where('email', $validatedData['email'])->first();

        if (!$user || !Hash::check($validatedData['password'], $user->password)) {
            return response()->json([
                'message' => 'Invalid email or password',
                'status' => 0
            ], 401);
        }

        $token = $user->createToken('Auth Token')->accessToken;

        return response()->json([
            'message' => 'User logged in successfully',
            'user' => $user,
            'token' => $token,
            'status' => 1
        ], 200);
    }


    public function getUser($id) {
        $user = User::find($id);

        if(is_null($user)) {
            return response()->json([
                'user' => null,
                'message' => 'User not Found',
                'status' => 0
            ]);
        }
        else {
            return response()->json([
                'user' => $user,
                'message' => 'User Found',
                'status' => 0
            ]);
        }
    }
}
