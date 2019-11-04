$(function() {
    $.ajax({
        url: '/jwt',
        data: {
            jwt: $("#jwt").text()
        },
        success: function(result) {
            $("#jwt_status").html(result);
        },
        error: function() {
            $("#jwt_status").html("ERROR");
        }
    });

    $.ajax({
        url: '/token',
        data: {
            token: $("#token").text()
        },
        success: function(result) {
            $("#token_status").html(result);
        },
        error: function() {
            $("#token_status").html("ERROR");
        }
    });
});
