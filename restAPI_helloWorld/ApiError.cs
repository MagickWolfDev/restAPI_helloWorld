namespace restAPI_helloWorld
{
    public class ApiError
    {
        public int Code { get; set; }
        public string? Message { get; set; }

        public ApiError(int code, string? message)
        {
            Code=code;
            Message=message;
        }
    }
}
