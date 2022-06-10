from flask import jsonify
from flask_jwt_extended import get_jwt
from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from common import sessionmaker, ResponseDoc
from .sessions_db import BlockedModToken
from ..base import MUBNamespace, Moderator, Permission

mub_base_namespace = MUBNamespace("base", sessionmaker=sessionmaker, path="")


@mub_base_namespace.route("/sign-in/")
class SignInResource(Resource):
    parser: RequestParser = RequestParser()
    parser.add_argument("username", type=str, required=True)
    parser.add_argument("password", type=str, required=True)

    @mub_base_namespace.doc_responses(ResponseDoc(description="Success with user's permissions"))  # TODO redo
    @mub_base_namespace.doc_aborts(("200 ", "Moderator does not exist"), (" 200", "Wrong password"))
    @mub_base_namespace.with_optional_jwt()
    @mub_base_namespace.with_begin
    @mub_base_namespace.argument_parser(parser)
    def post(self, session, username: str, password: str):
        moderator = Moderator.find_by_name(session, username)
        if moderator is None:
            return "Moderator does not exist"

        if Moderator.verify_hash(password, moderator.password):
            response = moderator.get_permissions(session)
            response = jsonify(mub_base_namespace.marshal(response, Permission.IndexModel))
            mub_base_namespace.add_authorization(response, moderator, "mub")
            return response
        return "Wrong password"


@mub_base_namespace.route("/sign-out/")
class SignInResource(Resource):
    @mub_base_namespace.jwt_authorizer(Moderator, check_only=True)
    def post(self, session):
        response = jsonify(True)
        BlockedModToken.create(session, jti=get_jwt()["jti"])
        mub_base_namespace.remove_authorization(response, "mub")
        return response


@mub_base_namespace.route("/my-permissions/")
class PermissionsResource(Resource):
    @mub_base_namespace.jwt_authorizer(Moderator)  # TODO pagination?
    @mub_base_namespace.marshal_list_with(Permission.IndexModel)
    def get(self, session, moderator):
        return moderator.get_permissions(session)
