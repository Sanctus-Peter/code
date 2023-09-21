from fastapi import APIRouter, status, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models import user_models, User
from app.schemas.user_schemas import UserResponse, UserBankSchema, ResponseData, UserData, AllUserData
from app.services.user_services import get_user, get_admin_user

router = APIRouter(tags=["Users"], prefix="/api/user")


@router.get("/profile", status_code=status.HTTP_200_OK, response_model=UserResponse)
async def get_user_profile(
        user: user_models.User = Depends(get_user)
):
    """
    Get user profile

    This endpoint returns the pofile of an authenticated user

     Args:
        user: The user making the request

    Returns:
        The user information
    """
    return {
        'message': 'User data fetched successfully',
        'statusCode': 200,
        'data': {
            'email': user.email,
            'isAdmin': user.is_admin,
            'name': user.last_name + ' ' + user.first_name,
            'phone_number': user.phone,
            'bank_name': user.bank_name,
            'bank_code': user.bank_code,
            'bank_number': user.bank_number
        }
    }


@router.post('/bank', status_code=status.HTTP_201_CREATED)
async def user_bank_details(
    data: UserBankSchema, db: Session = Depends(get_db),
    user: user_models.User = Depends(get_user)
):
    """

    """
    user.bank_number = data.bank_number
    user.bank_code = data.bank_code
    user.bank_name = data.bank_name

    db.commit()
    db.refresh(user)
    return {
        'message': 'successfully created bank account',
        'statusCode': 201
    }


@router.get("/users", status_code=status.HTTP_200_OK, response_model=ResponseData)
def get_all_users(db: Session = Depends(get_db), role: user_models.User = Depends(get_admin_user)):
    """
    Get all users from the database.

    Args:
        db (Session): SQLAlchemy database session.
        role: (admin user)

    Returns:
        ResponseData: Response data in the specified format.
    """
    users = db.query(User).filter(User.org_id == role.org_id).all()

    # Transform user data into AllUserData model instances
    user_data = [
        AllUserData(
            name=user.first_name + ' ' + user.last_name,
            email=user.email,
            profile_picture=user.profile_pic,
            user_id=user.id
        ) for user in users
    ]

    response_data = ResponseData(
        message="successfully retrieved user data",
        statusCode=200,
        data=user_data,
    )
    return response_data
