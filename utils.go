package auth

// String returns a pointer to of the string value passed in.
func String(v string) *string {
    return &v
}