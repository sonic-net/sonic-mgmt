import functions_framework


# Register an HTTP function with the Functions Framework
@functions_framework.http
def helloGET(request):
    # Your code here

    # Return an HTTP response
    return "OK"
