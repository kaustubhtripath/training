

<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
/*
class CreateAuthorsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     
    public function up()
    {
        Schema::create('authors', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');

            $table->timestamp('email_verified_at')->nullable();
            

            //  $table->string('email')->unique(); //have to make these
            //  $table->string('password');
            $table->rememberToken();  //used for forgot password functionality
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     
    public function down()
    {
        Schema::dropIfExists('authors');
    }
}
*/