using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        string AWS_ACCESS_KEY_ID="AKIA1234567890TESTKEY"; //FP due to length and keyword `TEST`
        string AWS_ACCESS_KEY_ID="AKIA123456789T1STKEY";  //TP
        
        string dbPassword="P@ssw0rdc123";


        string jwtSecret1= "super_secret_key_123456"; //FP as it is used anywhere
        var json = new JwtBuilder()
        .Decode<IDictionary<string, object>>(jwtToken)
        .WithSecret("super_secret_key_123456");       // TP
    }
}