# SKYST3_back

    [Register API]
    POST /api/register
    Registers a new user.

    Allowed instruments:
    - keyboard
    - vocal
    - bass
    - drum
    - guitar
    - etc

    Request Body Example (JSON):
    {
        "username": "amugae_kim",
        "password": "securepassword123",
        "name": "nickname",
        "email": "kim@example.com",
        "instrument": "guitar",
        "address": "서울특별시 성북구 안암동 123-45"
    }

    Responses:
    - 200 OK: User registered successfull
		       zip_code automatically calculated in the backend and assigned to the database
    - 400 Bad Request: Username or email already exists


    [Login API]
    POST /api/login
    Authenticates an existing user with username and password.

    Request Body Example (JSON):
    {
        "username": "amugae_kim",
        "password": "securepassword123"
    }

    Responses:
    - 200 OK: Returns a welcome message
    - 401 Unauthorized: Invalid username or password
    - access_token should be set in Authorization: Bearer

    		[Get Current User Info]
    GET /api/me
    Returns information about the currently authenticated user.
    Requires a valid JWT access token provided in the Authorization header as a Bearer token.

    Response Example (200 OK):
    {
        "username": "amugae_kim",
        "name": "nickname",
        "instrument": "guitar",
        "zip_code": "12345"
        "address": "서울특별시 성북구"
    }

    Responses:
    - 200 OK: Successfully returns current user's profile.
    - 401 Unauthorized: Missing or invalid authentication token.

    
    [Get User Area]
    GET /api/get_user_area
    Returns area and district (gu) name based on the given zip code.
    Uses KoZIP to convert zip code to address and determines the area accordingly.

    Query Parameters [GET]:
    zip_code (string): User's zip code

    Response Example (200 OK):
    {
        "area": "area2",
        "gu": "마포구"
    }

    Responses:
    200 OK: Successfully returns area and gu name
    400 Bad Request: Invalid zip code format or lookup error
    404 Not Found: No matching area found for the provided zip code


    POST /api/queue/part_random
    [part random api]
    Attempts to match the user with a room using part-random logic (no duplicate instruments).
    Creates a new room if no matching room is found.

    Requires authentication via Bearer token.

    Valid time_slot values:
    morning
    afternoon
    evening

    Allowed instruments:
    keyboard
    vocal
    bass
    drum
    guitar
    etc

    Allowed genre:
    Jpop
    Kpop
    indieBand
    heavyMetal
    hiphop

    Request Body Example (JSON):
    {
        "start_date": "2025-06-01",
        "end_date": "2025-06-05",
        "time_slot": "evening",
        "genre": "rock",
        "instrument": "bass"
    }

    Responses:
    200 OK: Successfully joined an existing or newly created room
    400 Bad Request: Request data is invalid or room join logic fails


    POST /api/queue/true_random
    [true random api]
    Attempts to match the user with a room using true-random logic (악기 선호 신경 X)
    Creates a new room if no matching room is found.

    Requires authentication via Bearer token.

    Valid time_slot values:
    morning
    afternoon
    evening

    Allowed genre:
    Jpop
    Kpop
    indieBand
    heavyMetal
    hiphop

    Request Body Example (JSON)
    {
        "start_date": "2025-06-01",
        "end_date": "2025-06-05",
        "time_slot": "evening",
        "genre": "rock"
    }

    Responses:
    200 OK: Successfully joined an existing or newly created room
    400 Bad Request: Request data is invalid or room join logic fails


    [Get Room People Count]
    GET /api/room/people_count

    Returns the number of people currently in a room specified by its room code.

    Query Parameters:

    room_code (string): The unique code identifying the room

    Response Example (200 OK):
    {
        "room_code": "X7Y8Z9",
        "people_count": 3
    }

    Responses:
    200 OK: Successfully returns the current number of members in the room
    404 Not Found: Room with the given code does not exist


    [Edit Profile API]
    POST /api/edit_profile

    Updates the current user's name, instrument, and address.  
    Automatically updates the zip code based on the new address.

    Requires a valid JWT token in the Authorization header.

    Request Body Example (JSON):
    {
        "name": "new nickname",
        "instrument": "drum",
        "address": "서울특별시 마포구"
    }

    Responses:
    - 200 OK: Profile updated successfully
    - 400 Bad Request: Invalid address (unable to resolve zip code)


