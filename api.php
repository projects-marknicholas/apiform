<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: *");

require 'vendor/autoload.php'; // Include Composer autoloader

// Include configuration
include 'config.php';

// Function to sanitize input
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Function to send verification email
function sendmail($firstname, $to, $subject, $verificationCode) {
    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message($subject))
        ->setFrom(['razonmarknicholas.cdlb@gmail.com' => 'APIForm'])
        ->setTo([$to])
        ->setBody(
            '<html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 20px;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #333;
                    }
                    p {
                        color: #555;
                    }
                    .verification-code {
                        font-size: 24px;
                        font-weight: bold;
                        color: #3498db;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Account Verification Code</h1>
                    <p>Dear ' . $firstname . ',</p>
                    <p>Your verification code is: <span class="verification-code">' . $verificationCode . '</span></p>
                    <p>Thank you for registering!</p>
                </div>
            </body>
            </html>',
            'text/html'
        );

    // Send the message
    $result = $mailer->send($message);

    // Check if the email was sent successfully
    if ($result > 0) {
        // Email sent successfully
        return true;
    } else {
        // Email not sent
        return false;
    }
}

// Function to handle registration API
function register() {
    global $pdo;  // Make $pdo variable available in this function
    $subject = "APIForm Account Verification";

    // Assuming you receive registration data in the POST request
    $firstname = isset($_POST['firstname']) ? sanitizeInput($_POST['firstname']) : null;
    $lastname = isset($_POST['lastname']) ? sanitizeInput($_POST['lastname']) : null;
    $email = isset($_POST['email']) ? sanitizeInput($_POST['email']) : null;
    $password = isset($_POST['password']) ? sanitizeInput($_POST['password']) : null;
    $confirmPassword = isset($_POST['confirm_password']) ? sanitizeInput($_POST['confirm_password']) : null;

    // Check if all required fields are provided
    if ($firstname && $lastname && $email && $password && $confirmPassword) {
        // Check if passwords match
        if ($password === $confirmPassword) {
            // Check if the email already exists in the database
            $stmtCheckEmail = $pdo->prepare('SELECT COUNT(*) FROM accounts WHERE email = ?');
            $stmtCheckEmail->execute([$email]);
            $emailExists = (bool)$stmtCheckEmail->fetchColumn();

            if (!$emailExists) {
                // Generate a unique user token using uniqid
                $userToken = uniqid('token_', true);

                // Generate a 6-digit code
                $verificationCode = sprintf('%06d', mt_rand(0, 999999));

                // Hash the password for security
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

                try {
                    // Send verification email
                    $emailSent = sendmail($firstname, $email, $subject, $verificationCode);

                    if ($emailSent) {
                        // Insert data into the accounts table using a prepared statement
                        $stmt = $pdo->prepare('INSERT INTO accounts (userToken, firstname, lastname, email, password, creationDate, code) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)');
                        $stmt->execute([$userToken, $firstname, $lastname, $email, $hashedPassword, $verificationCode]);

                        // Respond with a success message
                        $response = array('success' => true, 'message' => 'Registration successful');
                    } else {
                        $response = array('success' => false, 'message' => 'Error sending verification email');
                    }
                } catch (PDOException $e) {
                    $response = array('success' => false, 'message' => 'Error inserting data into the database');
                }
            } else {
                $response = array('success' => false, 'message' => 'Email already exists. Please use a different email address.');
            }
        } else {
            $response = array('success' => false, 'message' => 'Passwords do not match');
        }
    } else {
        $response = array('success' => false, 'message' => 'All fields are required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle account verification API
function verifyAccount() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive verification code in the POST request
    $verificationCode = isset($_POST['verification_code']) ? sanitizeInput($_POST['verification_code']) : null;

    // Check if the verification code is provided
    if ($verificationCode) {
        try {
            // Verify the account based on the provided verification code
            $stmt = $pdo->prepare('SELECT id, userToken, email FROM accounts WHERE code = ?');
            $stmt->execute([$verificationCode]);
            $account = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($account) {
                if ($account['status'] !== 'verified') {
                    // Update the account as verified
                    $stmtUpdate = $pdo->prepare('UPDATE accounts SET status = "verified" WHERE id = ?');
                    $stmtUpdate->execute([$account['id']]);

                    // Respond with a success message
                    $response = array('success' => true, 'message' => 'Account verification successful');
                } else {
                    $response = array('success' => false, 'message' => 'Account is already verified');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid verification code');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error verifying account');
        }
    } else {
        $response = array('success' => false, 'message' => 'Verification code is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle login API
function login() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive email and password in the POST request
    $email = isset($_POST['email']) ? $_POST['email'] : null;
    $password = isset($_POST['password']) ? $_POST['password'] : null;

    // Check if both email and password are provided
    if ($email && $password) {
        try {
            // Fetch user information from the database based on the provided email
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email, creationDate, password, status, code FROM accounts WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // Check if the user is verified
                if ($user['status'] == 'verified') {
                    // Verify the provided password against the hashed password stored in the database
                    if (password_verify($password, $user['password'])) {
                        // Generate a new 6-digit code
                        $newVerificationCode = sprintf('%06d', mt_rand(0, 999999));

                        // Update the code in the database
                        $updateCodeStmt = $pdo->prepare('UPDATE accounts SET code = ? WHERE email = ?');
                        $updateCodeStmt->execute([$newVerificationCode, $email]);

                        // User logged in successfully

                        // Serialize user data
                        $userData = array(
                            'userToken' => $user['userToken'],
                            'firstname' => $user['firstname'],
                            'lastname' => $user['lastname'],
                            'email' => $user['email'],
                            'creationDate' => $user['creationDate']
                        );
                        $userDataSerialized = json_encode($userData);

                        // Set a cookie with serialized user data
                        setcookie('user_data', $userDataSerialized, time() + (30 * 24 * 60 * 60), '/'); // Change 'user_data' to the desired cookie name

                        $response = array(
                            'success' => true,
                            'message' => 'Login successful',
                            'user' => $userData
                        );
                    } else {
                        $response = array('success' => false, 'message' => 'Invalid credentials');
                    }
                } else {
                    $response = array('success' => false, 'message' => 'Account not verified. Please check your email for verification instructions.');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid credentials. User not found');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Email and password are required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle forgot password API
function forgotPassword() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive email in the POST request
    $email = isset($_POST['email']) ? $_POST['email'] : null;

    // Check if email is provided
    if ($email) {
        try {
            // Fetch user information from the database based on the provided email
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email FROM accounts WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // Generate a unique reset token using userToken
                $resetToken = $user['userToken'];

                // Send reset password email with a link containing the reset token
                $resetLink = 'http://localhost/apiform-ui/reset-password?token='.$resetToken;
                //$resetLink = 'http://localhost/apiform/reset-password?token=' . $resetToken; // Update with your domain
                $subject = "APIForm Reset Password";
                $emailSent = sendResetPasswordEmail($email, $subject, $resetLink);

                if ($emailSent) {
                    // Respond with a success message
                    $response = array('success' => true, 'message' => 'Reset password instructions sent to your email');
                } else {
                    $response = array('success' => false, 'message' => 'Error sending reset password instructions');
                }
            } else {
                $response = array('success' => false, 'message' => 'Email not found');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Email is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to send reset password email
function sendResetPasswordEmail($to, $subject, $resetLink) {
    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message($subject))
        ->setFrom(['razonmarknicholas.cdlb@gmail.com' => 'APIForm'])
        ->setTo([$to])
        ->setBody(
            'Click the following link to reset your password: <a href="' . $resetLink . '">Click here</a>',
            'text/html'
        );

    // Send the message
    $result = $mailer->send($message);

    // Check if the email was sent successfully
    return $result > 0;
}

// Function to handle resetting the password based on the tokenNumber
function resetPassword($tokenNumber) {
    global $pdo;  // Make $pdo variable available in this function

    // Check if the tokenNumber is provided
    if ($tokenNumber) {
        try {
            // Fetch user information from the database based on the provided tokenNumber
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email FROM accounts WHERE userToken = ?');
            $stmt->execute([$tokenNumber]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // TODO: Implement the logic to check if the token is still valid (e.g., not expired)

                // Check if the new password and confirm password are provided and match
                $newPassword = isset($_POST['new_password']) ? $_POST['new_password'] : null;
                $confirmPassword = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : null;

                if ($newPassword && $confirmPassword && $newPassword === $confirmPassword) {
                    // Hash the new password
                    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);

                    // Update the user's password in the database
                    $updatePasswordStmt = $pdo->prepare('UPDATE accounts SET password = ? WHERE userToken = ?');
                    $updatePasswordStmt->execute([$hashedPassword, $tokenNumber]);

                    // Respond with a success message
                    $response = array('success' => true, 'message' => 'Password reset successful');
                } else {
                    $response = array('success' => false, 'message' => 'New password and confirm password do not match');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid or expired token');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Token number is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to create form into the forms table
function createForm($userToken) {
    global $pdo;  // Make $pdo variable available in this function

    // Retrieve form data from $_POST
    $formName = isset($_POST['form_name']) ? sanitizeInput($_POST['form_name']) : null;
    $enableForm = "true";
    $successUrl = isset($_POST['success_url']) ? sanitizeInput($_POST['success_url']) : null;
    $failedUrl = isset($_POST['failed_url']) ? sanitizeInput($_POST['failed_url']) : null;
    $formToken = uniqid('form_', true);

    // Validate input
    if (!$userToken || !$formName || $enableForm === false || !$successUrl || !$failedUrl) {
        // Invalid input
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Invalid input'));
        return false;
    }

    try {
        // Begin a transaction
        $pdo->beginTransaction();

        // Insert form data into the forms table using a prepared statement
        $stmt = $pdo->prepare('INSERT INTO forms (form_token, user_token, form_name, enable_form, success_url, failed_url) VALUES (?, ?, ?, ?, ?, ?)');
        $stmt->execute([$formToken, $userToken, $formName, $enableForm, $successUrl, $failedUrl]);

        // Check if the form was inserted successfully
        if ($stmt->rowCount() > 0) {
            // Commit the transaction if successful
            $pdo->commit();
            http_response_code(201); // Created
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Form created successfully'));
            return true;
        } else {
            // Rollback the transaction if the form insertion fails
            $pdo->rollBack();
            http_response_code(500); // Internal Server Error
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Failed to create form'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to update form in the forms table
function updateForm($formToken) {
    global $pdo;  // Make $pdo variable available in this function

    // Validate form token
    if (empty($formToken)) {
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Form token is required'));
        return false;
    }

    // Retrieve form data from $_POST
    $formName = isset($_POST['form_name']) ? sanitizeInput($_POST['form_name']) : null;
    $enableForm = isset($_POST['enable_form']) ? sanitizeInput($_POST['enable_form']) : null;
    $successUrl = isset($_POST['success_url']) ? sanitizeInput($_POST['success_url']) : null;
    $failedUrl = isset($_POST['failed_url']) ? sanitizeInput($_POST['failed_url']) : null;

    // Check if any changes were made to the data
    if ($formName === null && $enableForm === null && $successUrl === null && $failedUrl === null) {
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'No changes were made to the form data.'));
        return false;
    }

    try {
        // Begin a transaction
        $pdo->beginTransaction();

        // Check if the form with the given token exists
        $stmtCheck = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE form_token = ?');
        $stmtCheck->execute([$formToken]);
        $formExists = $stmtCheck->fetchColumn();

        if ($formExists > 0) {
            // Update form data in the forms table using a prepared statement
            $stmt = $pdo->prepare('UPDATE forms SET form_name = ?, enable_form = ?, success_url = ?, failed_url = ? WHERE form_token = ?');
            $stmt->execute([$formName, $enableForm, $successUrl, $failedUrl, $formToken]);

            // Check if the form was updated successfully
            if ($stmt->rowCount() > 0) {
                // Commit the transaction if successful
                $pdo->commit();
                http_response_code(200); // OK
                header('Content-Type: application/json');
                echo json_encode(array('message' => 'Form updated successfully'));
                return true;
            } else {
                // Rollback the transaction if the form update fails
                $pdo->rollBack();
                http_response_code(500); // Internal Server Error
                header('Content-Type: application/json');
                echo json_encode(array('message' => 'Failed to update form'));
                return false;
            }
        } else {
            // Rollback the transaction if the form does not exist
            $pdo->rollBack();
            http_response_code(404); // Not Found
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Form not found'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to read forms for a specific user from the forms table
function readForms($userToken) {
    global $pdo;  // Make $pdo variable available in this function

    // Validate user token
    if (empty($userToken)) {
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'User token is required'));
        return false;
    }

    try {
        // Select all forms for the given user token
        $stmt = $pdo->prepare('SELECT form_token, form_name, enable_form, success_url, failed_url FROM forms WHERE user_token = ? ORDER BY id DESC');
        $stmt->execute([$userToken]);

        // Fetch the result as an associative array
        $forms = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Check if forms were found
        if ($forms) {
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode($forms);
            return true;
        } else {
            http_response_code(404); // Not Found
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'No forms found for the specified user'));
            return false;
        }
    } catch (PDOException $e) {
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to read forms for a specific form from the forms table
function readFormsByFormToken($userToken, $formToken) {
    global $pdo;  // Make $pdo variable available in this function

    // Validate user token and form token
    if (empty($userToken) || empty($formToken)) {
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'User token and form token are required'));
        return false;
    }

    try {
        // Select form details for the given form token and user token
        $stmt = $pdo->prepare('SELECT form_token, form_name, enable_form, success_url, failed_url FROM forms WHERE user_token = ? AND form_token = ?');
        $stmt->execute([$userToken, $formToken]);

        // Fetch the result as an associative array
        $form = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if form was found
        if ($form) {
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode($form);
            return true;
        } else {
            // Check if the user has authority to access the specified form
            $stmtCheckAuthority = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE user_token = ? AND form_token = ?');
            $stmtCheckAuthority->execute([$userToken, $formToken]);
            $authorityCount = $stmtCheckAuthority->fetchColumn();

            if ($authorityCount > 0) {
                http_response_code(403); // Forbidden
                header('Content-Type: application/json');
                echo json_encode(array('message' => 'User does not have authority to access the specified form'));
                return false;
            } else {
                http_response_code(404); // Not Found
                header('Content-Type: application/json');
                echo json_encode(array('message' => 'No form found for the specified token and user'));
                return false;
            }
        }
    } catch (PDOException $e) {
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}


// Function to delete form from the forms table
function deleteForm($formToken) {
    global $pdo;  // Make $pdo variable available in this function

    try {
        // Check if the form token is provided
        if (empty($formToken)) {
            http_response_code(400); // Bad Request
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Form token is required'));
            return false;
        }

        // Check if the form with the given token exists
        $stmt_check = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE form_token = ?');
        $stmt_check->execute([$formToken]);
        $formExists = $stmt_check->fetchColumn();

        if (!$formExists) {
            http_response_code(404); // Not Found
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Form not found'));
            return false;
        }

        // Begin a transaction
        $pdo->beginTransaction();

        // Delete the form from the forms table using a prepared statement
        $stmt = $pdo->prepare('DELETE FROM forms WHERE form_token = ?');
        $stmt->execute([$formToken]);

        // Check if the form was deleted successfully
        if ($stmt->rowCount() > 0) {
            // Commit the transaction if successful
            $pdo->commit();
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Form deleted successfully'));
            return true;
        } else {
            // Rollback the transaction if the form deletion fails
            $pdo->rollBack();
            http_response_code(500); // Internal Server Error
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Failed to delete form'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to create an email server
function createEmailServer($userToken, $formToken) {
    global $pdo;  // Make $pdo variable available in this function

    try {
        // Check if the user has authority to access the specified form
        $stmtCheckAuthority = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE user_token = ? AND form_token = ?');
        $stmtCheckAuthority->execute([$userToken, $formToken]);
        $authorityCount = $stmtCheckAuthority->fetchColumn();

        if ($authorityCount === 0) {
            http_response_code(403); // Forbidden
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Invalid user and form relationship'));
            return false;
        }

        // Retrieve email server data from $_POST
        $serverToken = uniqid('server_', true);
        $email = isset($_POST['email']) ? sanitizeInput($_POST['email']) : null;
        $name = isset($_POST['name']) ? sanitizeInput($_POST['name']) : null;
        $status = "pending";

        // Validate input
        if (empty($serverToken) || empty($userToken) || empty($formToken) || empty($email) || empty($name) || empty($status)) {
            // Invalid input
            http_response_code(400); // Bad Request
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'All fields are required'));
            return false;
        }

        // Check if the email is already associated with this form
        $stmtCheckDuplicateEmail = $pdo->prepare('SELECT COUNT(*) FROM email_servers WHERE user_token = ? AND form_token = ? AND email = ?');
        $stmtCheckDuplicateEmail->execute([$userToken, $formToken, $email]);
        $duplicateEmailCount = $stmtCheckDuplicateEmail->fetchColumn();

        if ($duplicateEmailCount > 0) {
            // Email already exists for this form
            http_response_code(400); // Bad Request
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Email already exists in the form'));
            return false;
        }

        // Begin a transaction
        $pdo->beginTransaction();

        // Insert email server data into the email_servers table using a prepared statement
        $stmt = $pdo->prepare('INSERT INTO email_servers (server_token, user_token, form_token, email, name, status) VALUES (?, ?, ?, ?, ?, ?)');
        $stmt->execute([$serverToken, $userToken, $formToken, $email, $name, $status]);

        // Check if the email server was inserted successfully
        if ($stmt->rowCount() > 0) {
            // Commit the transaction if successful
            $pdo->commit();
            http_response_code(201); // Created
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Email server created successfully'));
            return true;
        } else {
            // Rollback the transaction if the email server insertion fails
            $pdo->rollBack();
            http_response_code(500); // Internal Server Error
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Failed to create email server'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to read all email servers for a specific user and form from the email_servers table
function readAllEmailServers($userToken, $formToken) {
    global $pdo;  // Make $pdo variable available in this function

    try {
        // Check if the user has authority to access the specified form
        $stmtCheckAuthority = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE user_token = ? AND form_token = ?');
        $stmtCheckAuthority->execute([$userToken, $formToken]);
        $authorityCount = $stmtCheckAuthority->fetchColumn();

        if ($authorityCount === 0) {
            http_response_code(403); // Forbidden
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Invalid user and form relationship'));
            return false;
        }

        // Select all email servers for the given user and form
        $stmt = $pdo->prepare('SELECT id, server_token, email, name, status FROM email_servers WHERE user_token = ? AND form_token = ?');
        $stmt->execute([$userToken, $formToken]);

        // Fetch the result as an associative array
        $emailServers = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Check if email servers were found
        if ($emailServers) {
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode($emailServers);
            return true;
        } else {
            http_response_code(404); // Not Found
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'No email servers found for the specified user and form'));
            return false;
        }
    } catch (PDOException $e) {
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

/// Function to update email server in the email_servers table
function updateEmailServer($userToken, $formToken, $serverToken, $statusParam = null) {
    global $pdo;  // Make $pdo variable available in this function

    // Define verified status values
    $verifiedStatusValues = array('verified');

    // Retrieve email server data from $_POST
    $name = isset($_POST['name']) ? sanitizeInput($_POST['name']) : null;
    
    // Use the provided $statusParam if available, otherwise, check $_POST
    $status = isset($statusParam) ? sanitizeInput($statusParam) : (isset($_POST['status']) ? sanitizeInput($_POST['status']) : null);

    // Validate input
    if (empty($userToken) || empty($formToken) || empty($serverToken) || !in_array($status, $verifiedStatusValues)) {
        // Invalid input
        http_response_code(400); // Bad Request
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Invalid input. Provide valid values for all fields.'));
        return false;
    }

    try {
        // Check if the user has authority to access the specified form
        $stmtCheckAuthority = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE user_token = ? AND form_token = ?');
        $stmtCheckAuthority->execute([$userToken, $formToken]);
        $authorityCount = $stmtCheckAuthority->fetchColumn();

        if ($authorityCount === 0) {
            http_response_code(403); // Forbidden
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Invalid user and form relationship'));
            return false;
        }

        // Begin a transaction
        $pdo->beginTransaction();

        // Update email server data in the email_servers table using a prepared statement
        $stmt = $pdo->prepare('UPDATE email_servers SET name = COALESCE(?, name), status = COALESCE(?, status) WHERE user_token = ? AND form_token = ? AND server_token = ?');
        $stmt->execute([$name, $status, $userToken, $formToken, $serverToken]);

        // Check if the email server was updated successfully
        if ($stmt->rowCount() > 0) {
            // Commit the transaction if successful
            $pdo->commit();
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Email server updated successfully'));
            return true;
        } else {
            // Rollback the transaction if the email server update fails
            $pdo->rollBack();
            http_response_code(500); // Internal Server Error
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Failed to update email server'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to delete an email server by server_token
function deleteEmailServerByToken($userToken, $formToken, $serverToken) {
    global $pdo;  // Make $pdo variable available in this function

    try {
        // Check if the user has authority to access the specified form
        $stmtCheckAuthority = $pdo->prepare('SELECT COUNT(*) FROM forms WHERE user_token = ? AND form_token = ?');
        $stmtCheckAuthority->execute([$userToken, $formToken]);
        $authorityCount = $stmtCheckAuthority->fetchColumn();

        if ($authorityCount === 0) {
            http_response_code(403); // Forbidden
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Invalid user and form relationship'));
            return false;
        }

        // Begin a transaction
        $pdo->beginTransaction();

        // Delete the email server by server_token
        $stmt = $pdo->prepare('DELETE FROM email_servers WHERE user_token = ? AND form_token = ? AND server_token = ?');
        $stmt->execute([$userToken, $formToken, $serverToken]);

        // Check if the email server was deleted successfully
        if ($stmt->rowCount() > 0) {
            // Commit the transaction if successful
            $pdo->commit();
            http_response_code(200); // OK
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Email server deleted successfully'));
            return true;
        } else {
            // Rollback the transaction if the email server deletion fails
            $pdo->rollBack();
            http_response_code(404); // Not Found
            header('Content-Type: application/json');
            echo json_encode(array('message' => 'Email server not found or failed to delete'));
            return false;
        }
    } catch (PDOException $e) {
        // Rollback the transaction on exception
        $pdo->rollBack();
        http_response_code(500); // Internal Server Error
        header('Content-Type: application/json');
        echo json_encode(array('message' => 'Internal server error'));
        return false;
    }
}

// Function to send invitation email with clickable link
function sendInvitationEmailWithLink($userToken, $formToken, $serverToken) {
    global $pdo;

    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    try {
        // Retrieve email and name from the email_servers table based on serverToken
        $stmtEmailName = $pdo->prepare('SELECT email, name FROM email_servers WHERE server_token = ?');
        $stmtEmailName->execute([$serverToken]);

        // Fetch the result
        $resultEmailName = $stmtEmailName->fetch(PDO::FETCH_ASSOC);

        // Check if email and name are found
        $email = ($resultEmailName && isset($resultEmailName['email'])) ? $resultEmailName['email'] : null;
        $name = ($resultEmailName && isset($resultEmailName['name'])) ? $resultEmailName['name'] : null;

        // Check if email is found
        if (!$email) {
            throw new Exception('Email not found');
        }

        // Retrieve form name from the database
        $stmtForm = $pdo->prepare('SELECT form_name FROM forms WHERE form_token = ?');
        $stmtForm->execute([$formToken]);

        // Fetch the result
        $resultForm = $stmtForm->fetch(PDO::FETCH_ASSOC);

        // Check if form name is found
        $formName = ($resultForm && isset($resultForm['form_name'])) ? $resultForm['form_name'] : null;

        // Check if form is found
        if (!$formName) {
            throw new Exception('Form not found');
        }

        // Check if user is found
        if (!$name) {
            throw new Exception('User not found');
        }

        // Create a message with clickable link
        $message = (new Swift_Message('Invitation to Receive Form Submissions'))
            ->setFrom([$email => 'APIForm'])
            ->setTo([$email])
            ->setBody(
                '<html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 20px;
                        }
                        .container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #fff;
                            padding: 20px;
                            border-radius: 5px;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }
                        h1 {
                            color: #333;
                        }
                        p {
                            color: #555;
                        }
                        .invitation-link {
                            font-size: 16px;
                            color: #3498db;
                            text-decoration: none;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">'
                        . ($name ? '<p>Dear ' . sanitizeInput($name) . ',</p>' : '<p>Dear Maam/Sir,</p>')
                        . ($formName ? '<p>You have been invited to receive submissions for the form <strong>' . sanitizeInput($formName) . '</strong>.</p>' : '')
                        . ($userToken && $formToken && $serverToken
                            ? '<p>Click the following link to accept the invitation: <a href="http://localhost/apiform/api/update-email-server/' . $userToken . '/' . $formToken . '/' . $serverToken . '/verified" class="invitation-link">Accept Invitation</a></p>'
                            : '')
                        . '<p>Thank you for participating!</p>
                    </div>
                </body>
                </html>',
                'text/html'
            );

        // Send the message
        $result = $mailer->send($message);

        // Check if the email was sent successfully
        if ($result > 0) {
            // Email sent successfully
            $response = array('success' => true, 'message' => 'Invitation email sent successfully');
        } else {
            // Email not sent
            throw new Exception('Failed to send invitation email');
        }
    } catch (Exception $e) {
        // Handle exceptions and return error message
        $response = array('success' => false, 'message' => $e->getMessage());
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle sending submission based on the formToken
function sendSubmission($formToken) {
    global $pdo;  // Make $pdo variable available in this function

    // Check if the formToken is provided
    if ($formToken) {
        try {
            // Fetch form information from the database based on the provided formToken
            $stmt = $pdo->prepare('SELECT form_token, user_token, form_name, enable_form, success_url, failed_url FROM forms WHERE form_token = ?');
            $stmt->execute([$formToken]);
            $form = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the form exists
            if ($form) {
                // Check if the form is enabled
                if ($form['enable_form']) {
                    // Fetch user information from the database based on the provided user_token
                    $userToken = $form['user_token'];
                    $userStmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email FROM accounts WHERE userToken = ?');
                    $userStmt->execute([$userToken]);
                    $user = $userStmt->fetch(PDO::FETCH_ASSOC);

                    // Check if the user exists
                    if ($user) {
                        // Iterate through all POST variables
                        $postData = array();
                        foreach ($_POST as $name => $val) {
                            $postData[] = htmlspecialchars($name . ': ' . $val);
                        }

                        // Compose a more professional and attractive HTML email body
                        $subject = 'New Message from ' . $form['form_name'];
                        $to = $user['email'];

                        $body = '
                            <html>
                                <head>
                                    <style>
                                        body {
                                            font-family: Arial, sans-serif;
                                            background-color: #f4f4f4;
                                            margin: 0;
                                            padding: 20px;
                                        }
                                        .container {
                                            max-width: 600px;
                                            margin: 0 auto;
                                            background-color: #fff;
                                            padding: 20px;
                                            border-radius: 5px;
                                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                                        }
                                        h1 {
                                            color: #333;
                                        }
                                        p {
                                            color: #555;
                                        }
                                        .submission-details {
                                            font-size: 16px;
                                            color: #333;
                                            margin-bottom: 20px;
                                        }
                                    </style>
                                </head>
                                <body>
                                    <div class="container">
                                        <h1>New Message from ' . $form['form_name'] . '</h1>
                                        <p>Dear ' . $user['firstname'] . ',</p>
                                        <p>You have received a new message from the form. Below are the details:</p>
                                        <div class="submission-details">
                                            ' . implode('<br>', $postData) . '
                                        </div>
                                        <p>Thank you for using our services!</p>
                                    </div>
                                </body>
                            </html>';

                        $emailSent = sendSubmissionEmail($to, $subject, $body);

                        if ($emailSent) {
                            // Redirect to the success URL if available, otherwise to the default URL
                            $successURL = !empty($form['success_url']) ? $form['success_url'] : 'http://localhost/apiform-ui';
                            header('Location: ' . $successURL);
                            exit;
                        } else {
                            // Redirect to the failed URL if available, otherwise to the default URL
                            $failedURL = !empty($form['failed_url']) ? $form['failed_url'] : 'http://localhost/apiform-ui';
                            header('Location: ' . $failedURL);
                            exit;
                        }
                    } else {
                        $response = array('success' => false, 'message' => 'User not found');
                    }
                } else {
                    $response = array('success' => false, 'message' => 'This form will not receive messages');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid formToken');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving form information');
        }
    } else {
        $response = array('success' => false, 'message' => 'formToken is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to send submission email using SwiftMailer
function sendSubmissionEmail($to, $subject, $body) {
    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message($subject))
        ->setFrom(['razonmarknicholas.cdlb@gmail.com' => 'APIForm'])
        ->setTo([$to])
        ->setBody($body, 'text/html');

    // Send the message
    $result = $mailer->send($message);

    // Check if the email was sent successfully
    return $result > 0;
}

?>
