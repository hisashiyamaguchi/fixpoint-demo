"""
Demo views with XSS vulnerabilities.
Fixpoint will automatically detect and fix these!
"""
from django.utils.html import mark_safe, escape
from django.utils.safestring import SafeString


# =============================================================================
# VULNERABLE: XSS vulnerabilities that Fixpoint will fix
# =============================================================================

def render_user_comment(user_input):
    """
    VULNERABLE: mark_safe() with user input
    
    An attacker could input: <script>alert('XSS')</script>
    This would execute JavaScript in the browser!
    """
    # VULNERABLE - mark_safe with user input
    return mark_safe(user_input)


def render_profile_bio(bio_text):
    """
    VULNERABLE: mark_safe() with dynamic content
    """
    formatted_bio = f"<div class='bio'>{bio_text}</div>"
    # VULNERABLE - mark_safe with f-string containing user data
    return mark_safe(formatted_bio)


def render_notification(message):
    """
    VULNERABLE: SafeString() with user input
    """
    # VULNERABLE - SafeString with user input
    return SafeString(message)


def render_html_content(content):
    """
    VULNERABLE: mark_safe() in return statement
    """
    processed = content.replace("\n", "<br>")
    return mark_safe(processed)


class CommentRenderer:
    """Class with XSS vulnerabilities."""
    
    def render(self, text):
        """VULNERABLE: mark_safe in method."""
        return mark_safe(text)
    
    def render_with_wrapper(self, text):
        """VULNERABLE: SafeString in method."""
        wrapped = f"<span>{text}</span>"
        return SafeString(wrapped)


# =============================================================================
# SAFE: Already using escape() (Fixpoint will skip these)
# =============================================================================

def render_safe_comment(user_input):
    """
    SAFE: Using escape() to sanitize user input
    """
    return escape(user_input)


def render_safe_bio(bio_text):
    """
    SAFE: Escaping user input before rendering
    """
    safe_bio = escape(bio_text)
    return f"<div class='bio'>{safe_bio}</div>"


# =============================================================================
# SAFE: mark_safe with static content only (Fixpoint is smart about this)
# =============================================================================

def render_static_icon():
    """
    SAFE: mark_safe with static HTML (no user input)
    """
    return mark_safe("<i class='icon-check'></i>")


if __name__ == "__main__":
    # Demo usage
    user_comment = "<script>alert('XSS')</script>"
    
    # This is vulnerable!
    unsafe_output = render_user_comment(user_comment)
    print(f"Unsafe: {unsafe_output}")
    
    # This is safe
    safe_output = render_safe_comment(user_comment)
    print(f"Safe: {safe_output}")
