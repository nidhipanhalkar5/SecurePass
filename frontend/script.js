function showPassword() {

    const password = document.getElementById("password");

    if (password.type === "password") {

        password.type = "text";

    } else {

        password.type = "password";

    }

}
function login() {

    const password =
        document.getElementById("password").value;

    const message =
        document.getElementById("message");


    const correctPassword =
        "Demo@12345";


    if (password !== correctPassword) {

        message.style.color =
            "#f87171";

        message.textContent =
            "Incorrect master password.";

        return;

    }


    message.style.color =
        "#4ade80";

    message.textContent =
        "Vault unlocked successfully!";


    setTimeout(function() {

        window.location.href =
            "dashboard.html";

    }, 700);

}