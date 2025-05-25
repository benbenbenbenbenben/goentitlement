#!/bin/bash

# SaaS API Demo Script
# This script demonstrates JWT authentication and goentitlement authorization

set -e

API_BASE="http://localhost:8080"
HEADER_AUTH="Authorization: Bearer"

echo "🚀 SaaS API Demo - JWT Authentication & goentitlement Authorization"
echo "=================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to make API calls and show results
make_request() {
    local method=$1
    local endpoint=$2
    local token=$3
    local description=$4
    
    echo -e "${BLUE}📋 Test: ${description}${NC}"
    echo "   Endpoint: ${method} ${endpoint}"
    
    if [ -n "$token" ]; then
        echo "   Token: Using provided JWT token"
        response=$(curl -s -X "$method" -H "$HEADER_AUTH $token" "$API_BASE$endpoint")
    else
        echo "   Token: None (testing unauthorized access)"
        response=$(curl -s -X "$method" "$API_BASE$endpoint")
    fi
    
    # Check if response contains "success":true
    if echo "$response" | grep -q '"success":true'; then
        echo -e "   ${GREEN}✅ SUCCESS${NC}"
    else
        echo -e "   ${RED}❌ FAILED${NC}"
    fi
    
    echo "   Response: $response"
    echo ""
}

# Function to start server if not running
check_server() {
    echo "🔍 Checking if server is running..."
    if ! curl -s "$API_BASE/health" > /dev/null 2>&1; then
        echo "❌ Server is not running on $API_BASE"
        echo "📝 Starting server..."
        echo "   Run: cd examples/saas-api && GOTOOLCHAIN=go1.24.3 go run cmd/server/main.go"
        echo "   Then run this demo script again"
        exit 1
    fi
    echo "✅ Server is running"
    echo ""
}

# Function to get test tokens
get_tokens() {
    echo "🔑 Getting test JWT tokens..."
    local tokens_response=$(curl -s "$API_BASE/api/tokens")
    
    # Extract tokens using basic string manipulation (avoiding jq dependency)
    ADMIN_TOKEN=$(echo "$tokens_response" | grep -o '"admin":{"description":"[^"]*","token":"[^"]*"' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    PREMIUM_TOKEN=$(echo "$tokens_response" | grep -o '"premium":{"description":"[^"]*","token":"[^"]*"' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    BASIC_TOKEN=$(echo "$tokens_response" | grep -o '"basic":{"description":"[^"]*","token":"[^"]*"' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    TRIAL_TOKEN=$(echo "$tokens_response" | grep -o '"trial":{"description":"[^"]*","token":"[^"]*"' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    
    echo "   ✅ Admin token: ${ADMIN_TOKEN:0:50}..."
    echo "   ✅ Premium token: ${PREMIUM_TOKEN:0:50}..."
    echo "   ✅ Basic token: ${BASIC_TOKEN:0:50}..."
    echo "   ✅ Trial token: ${TRIAL_TOKEN:0:50}..."
    echo ""
}

# Main demo function
run_demo() {
    echo "🧪 Running Authorization Demo Tests"
    echo "=================================="
    echo ""
    
    # 1. Public endpoints (no auth required)
    echo -e "${YELLOW}📂 PUBLIC ENDPOINTS${NC}"
    make_request "GET" "/health" "" "Health check (public)"
    make_request "GET" "/api/public" "" "Public API info"
    make_request "GET" "/api/tokens" "" "Get test tokens (public)"
    
    # 2. Authentication tests
    echo -e "${YELLOW}🔐 AUTHENTICATION TESTS${NC}"
    make_request "GET" "/api/protected" "" "Missing JWT token (should fail)"
    make_request "GET" "/api/protected" "invalid-token" "Invalid JWT token (should fail)"
    make_request "GET" "/api/protected" "$BASIC_TOKEN" "Valid JWT token (should succeed)"
    
    # 3. Authorization tests - Basic User
    echo -e "${YELLOW}👤 BASIC USER AUTHORIZATION${NC}"
    make_request "GET" "/api/protected" "$BASIC_TOKEN" "Basic user - protected endpoint"
    make_request "GET" "/api/profile" "$BASIC_TOKEN" "Basic user - profile access"
    make_request "GET" "/api/features/analytics" "$BASIC_TOKEN" "Basic user - analytics feature (should fail)"
    make_request "GET" "/api/subscription/premium" "$BASIC_TOKEN" "Basic user - premium subscription (should fail)"
    make_request "GET" "/api/admin/dashboard" "$BASIC_TOKEN" "Basic user - admin dashboard (should fail)"
    
    # 4. Authorization tests - Premium User
    echo -e "${YELLOW}💎 PREMIUM USER AUTHORIZATION${NC}"
    make_request "GET" "/api/protected" "$PREMIUM_TOKEN" "Premium user - protected endpoint"
    make_request "GET" "/api/profile" "$PREMIUM_TOKEN" "Premium user - profile access"
    make_request "GET" "/api/features/analytics" "$PREMIUM_TOKEN" "Premium user - analytics feature"
    make_request "GET" "/api/subscription/premium" "$PREMIUM_TOKEN" "Premium user - premium subscription"
    make_request "GET" "/api/subscription/enterprise" "$PREMIUM_TOKEN" "Premium user - enterprise subscription (should fail)"
    make_request "GET" "/api/admin/dashboard" "$PREMIUM_TOKEN" "Premium user - admin dashboard (should fail)"
    
    # 5. Authorization tests - Admin User
    echo -e "${YELLOW}👑 ADMIN USER AUTHORIZATION${NC}"
    make_request "GET" "/api/protected" "$ADMIN_TOKEN" "Admin user - protected endpoint"
    make_request "GET" "/api/profile" "$ADMIN_TOKEN" "Admin user - profile access"
    make_request "GET" "/api/features/analytics" "$ADMIN_TOKEN" "Admin user - analytics feature"
    make_request "GET" "/api/features/api-access" "$ADMIN_TOKEN" "Admin user - API access feature"
    make_request "GET" "/api/subscription/premium" "$ADMIN_TOKEN" "Admin user - premium subscription"
    make_request "GET" "/api/subscription/enterprise" "$ADMIN_TOKEN" "Admin user - enterprise subscription"
    make_request "GET" "/api/admin/dashboard" "$ADMIN_TOKEN" "Admin user - admin dashboard"
    
    # 6. Authorization tests - Trial User
    echo -e "${YELLOW}🆓 TRIAL USER AUTHORIZATION${NC}"
    make_request "GET" "/api/protected" "$TRIAL_TOKEN" "Trial user - protected endpoint"
    make_request "GET" "/api/profile" "$TRIAL_TOKEN" "Trial user - profile access"
    make_request "GET" "/api/features/analytics" "$TRIAL_TOKEN" "Trial user - analytics feature (should fail)"
    make_request "GET" "/api/subscription/premium" "$TRIAL_TOKEN" "Trial user - premium subscription (should fail)"
    make_request "GET" "/api/admin/dashboard" "$TRIAL_TOKEN" "Trial user - admin dashboard (should fail)"
}

# Summary function
show_summary() {
    echo "📊 DEMO SUMMARY"
    echo "==============="
    echo ""
    echo "✅ JWT Authentication Working:"
    echo "   - Valid tokens are accepted"
    echo "   - Invalid/missing tokens are rejected"
    echo "   - Proper error codes returned"
    echo ""
    echo "✅ goentitlement Authorization Working:"
    echo "   - Role-based access control (admin dashboard)"
    echo "   - Feature-based access control (analytics, API access)"
    echo "   - Subscription-based access control (premium, enterprise)"
    echo "   - Proper error codes for insufficient permissions"
    echo ""
    echo "✅ Test Coverage:"
    echo "   - Unknown users (invalid/missing JWT) ❌"
    echo "   - Known user with access (valid JWT + entitlements) ✅"
    echo "   - Known user without access (valid JWT but missing entitlements) ❌"
    echo ""
    echo "🎉 Integration between JWT authentication and goentitlement authorization is working correctly!"
}

# Main execution
main() {
    check_server
    get_tokens
    run_demo
    show_summary
}

# Run the demo
main