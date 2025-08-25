"""
Owner: ICBMAY

Handles the functionality of the password strength checker.
"""
def check_password_strength(password: str) -> dict:
    score = 0
    recommendations = []

    # Length
    if len(password) >= 8:
        score += 1
    else:
        recommendations.append("Use at least 8 characters.")

    # Lowercase
    if any(c.islower() for c in password):
        score += 1
    else:
        recommendations.append("Include lowercase letters.")

    # Uppercase
    if any(c.isupper() for c in password):
        score += 1
    else:
        recommendations.append("Include uppercase letters.")

    # Digit
    if any(c.isdigit() for c in password):
        score += 1
    else:
        recommendations.append("Include numbers.")

    # Special character
    if any(c in "@#$%&*!?" for c in password):
        score += 1
    else:
        recommendations.append("Include special characters (@, #, $, %, &, *, !, ?).")

    # Label the strength
    if score >= 4:
        strength = "Strong"
    elif score == 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {
        "score": score,
        "strength": strength,
        "recommendations": recommendations
    }


if name == "main":
    while True:
        password = input("\nEnter your password: ")
        result = check_password_strength(password)

        print(f"\nPassword Strength: {result['strength']} (score {result['score']}/5)")

        if result["score"] == 5:
            print("\n✅ Great! Your password is very strong (5/5).")
            break
        else:
            # Show only what is still missing
            print("You still need to improve:")
            for rec in result['recommendations']:
                print(f"- {rec}")
            print("⚠️ Try again!")

       
