import datetime

from app import utils
from app.settings import oauth2
from app.utils import generate_otp, send_otp_to_email, OTPVerificationMixin
from fastapi import APIRouter, status, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import EmailStr

from app.models.organization_models import Organization, OrganizationInvite, OrganizationLaunchWallet
from app.schemas.organization_schemas import CreateOrganizationSchema, OrganizationSchema, CreateOrganizationUserSchema
from app.db.database import get_db
from app.models import user_models, User
from app.services.user_services import get_admin_user, get_user

router = APIRouter(tags=["Organizations"], prefix="/api/organization")


@router.post(
    "/create", status_code=status.HTTP_201_CREATED, response_model=OrganizationSchema
)
async def create_organization(
        org: CreateOrganizationSchema, db: Session = Depends(get_db),
        role: user_models.User = Depends(get_user)
):
    """
    Create an organization.

    This endpoint allows an admin user to create an organization

    Args:
        org: The organization details
        db: The database session
        role: The admin user making the request

    Returns:
        The created organization
    """
    if role.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User already is an admin to an organization"
        )
    new_org = org.model_dump()
    org_name = new_org.pop('organization_name')
    new_org['name'] = org_name
    new_org = Organization(**new_org)
    new_org.currency_code = 'NG'
    db.add(new_org)
    db.commit()
    db.refresh(new_org)

    role.org_id = new_org.id
    role.is_admin = True
    db.commit()
    return new_org


@router.post('/invite', status_code=status.HTTP_200_OK)
async def user_organization_invite(
    email: EmailStr, db: Session = Depends(get_db),
    role: user_models.User = Depends(get_admin_user)
):
    otp = generate_otp(role.org_id)
    org = db.query(Organization).filter(Organization.id == role.org_id).first()

    response, code = send_otp_to_email(role.email, email, role.org_id, org.name)

    if 200 <= int(response.status_code) < 300:
        org_instance = OrganizationInvite(
            email=email,
            token=code,
            org_id=role.org_id,
            ttl=datetime.datetime.now()
        )
        db.add(org_instance)
        db.commit()
        db.refresh(org_instance)
        return {
            'message': 'success',
            'statusCode': 200,
            'data': None,
        }
    else:
        raise HTTPException(status_code=status.HTTP_408_REQUEST_TIMEOUT, detail='There was an error sending the email')


@router.post('/staff/signup', status_code=status.HTTP_201_CREATED)
async def register_user_in_organization(
        user: CreateOrganizationUserSchema, db: Session = Depends(get_db)
):
    """
        User Signup

        Registers a new user in the database.

        Parameters:
        - user (CreateOrganizationUserSchema): Schema containing user information.
        - db (Session): SQLAlchemy Session object for database operations.

        Returns:
        - dict: Dictionary containing user information and access token.

        Raises:
        - HTTPException(409): If the user already exists.
    """
    usr_instance = db.query(User).filter(User.email == user.email).first()
    if usr_instance:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User already exists')

    org_instance = db.query(OrganizationInvite).filter(OrganizationInvite.token==user.otp_token).first()
    otp_mixin = OTPVerificationMixin()
    if not otp_mixin.verify_otp(user.otp_token, org_instance.org_id):
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail='Incorrect OTP')
    # existing_usr = db.query(User).filter(
    #     (User.org_id == org_instance.org_id) and (User.email == user.email)
    # ).first()
    # if existing_usr:
    #     raise HTTPException(
    #         status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=f"user with {user.email} already belongs to an organization"
    #     )
    new_user = User(
        email=user.email,
        password_hash=utils.hashed(user.password),
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone_number,
        is_admin=False,
        org_id=org_instance.org_id
    )
    db.add(new_user)
    db.delete(org_instance)
    db.commit()
    db.refresh(new_user)
    access_tok = oauth2.create_access_token(data={'user_id': new_user.id})
    return {
        'message': 'User registered successfully',
        'statusCode': 201,
        'data': {
            'access_token': access_tok,
            'email': new_user.email,
            'id': new_user.id,
            'isAdmin': new_user.is_admin
        }
    }


@router.post('/wallet/update', status_code=status.HTTP_200_OK)
async def update_wallet(
        balance: float, db: Session = Depends(get_db),
        role: user_models.User = Depends(get_admin_user)
):
    """
    Update Organization Wallet

    This endpoint allows an admin user to update the organization wallet

    Args:
        balance: The organization wallet balance
        db: The database session
        role: The admin user making the request

    Returns:
        The updated organization
    """
    org_instance = OrganizationLaunchWallet(
        balance=balance,
        org_id=role.org_id
    )
    db.add(org_instance)
    db.commit()
    db.refresh(org_instance)

    return {
        'message': 'success',
        'statusCode': 200,
        'data': None
    }


@router.put('lunch/update', status_code=status.HTTP_200_OK)
async def update_lunch_price(
        lunch_price: float, db: Session = Depends(get_db),
        role: user_models.User = Depends(get_admin_user)
):
    """
    Update Organization Wallet

    This endpoint allows an admin user to update the organization wallet

    Args:
        lunch_price: The organization wallet balance
        db: The database session
        role: The admin user making the request

    Returns:
        The updated organization
    """
    org_instance = db.query(Organization).filter(Organization.id == role.org_id).first()
    org_instance.lunch_price = lunch_price
    db.commit()
    db.refresh(org_instance)

    return {
        'message': 'success',
        'statusCode': 200,
        'data': None
    }
