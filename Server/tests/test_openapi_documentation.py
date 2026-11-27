from typing import TypedDict, cast

from fastapi.testclient import TestClient

from Server.main import app


class Parameter(TypedDict):
    name: str
    schema: dict[str, object]


class Operation(TypedDict):
    tags: list[str]
    security: list[dict[str, list[str]]]
    responses: dict[str, object]
    parameters: list[Parameter]


def test_swagger_and_openapi_contract() -> None:
    users = "/api/users"
    group = "/api/groups/{group_id}"
    archive = group + "/messages/{message_ref}"
    expected = {
        (users + "/{user_id}", "put"): ("Users", {403, 404, 422}),
        (users, "get"): ("Users", set[int]()),
        (users + "/{user_id}/key-packages/{package_id}", "put"): ("Users", {403, 404, 409, 422}),
        (users + "/{user_id}/key-packages/claims", "post"): ("Users", {404, 409, 422}),
        (group, "put"): ("Groups", {403, 409, 422}),
        (group + "/epochs/{epoch}", "put"): ("Groups", {403, 404, 409, 422}),
        (group + "/messages", "get"): ("Messages", {403, 404}),
        (archive, "put"): ("Messages", {403, 404, 409, 422}),
        (archive, "get"): ("Messages", {403, 404, 422}),
    }
    public = {
        "/api/registration-challenges": {"201", "404", "422", "429"},
        "/api/registrations": {"201", "404", "409", "422", "429"},
    }
    with TestClient(app) as client:
        docs = client.get("/docs")
        assert docs.status_code == 200 and "/openapi.json" in docs.text
        schema = client.get("/openapi.json")
        assert schema.status_code == 200

    paths = cast(dict[str, dict[str, Operation]], schema.json()["paths"])
    assert {(path, method) for path, item in paths.items() for method in item} == (
        set(expected) | {(path, "post") for path in public}
    )
    for path, statuses in public.items():
        op = paths[path]["post"]
        assert op["tags"] == ["Registration"]
        assert "security" not in op
        assert statuses <= op["responses"].keys()
    for (path, method), (tag, errors) in expected.items():
        op = paths[path][method]
        assert op["tags"] == [tag]
        assert len(op["security"]) == 1
        (scheme,) = op["security"][0]
        assert schema.json()["components"]["securitySchemes"][scheme]["type"] == "http"
        assert schema.json()["components"]["securitySchemes"][scheme]["scheme"] == "bearer"
        assert {str(code) for code in errors | {200, 401}} <= op["responses"].keys()

    for method, model in (("put", "ArchiveReceipt"), ("get", "ArchivedMessageResponse")):
        param = next(p["schema"] for p in paths[archive][method]["parameters"] if p["name"] == "message_ref")
        if method == "put":
            assert param["type"] == "string" and param["format"] == "uuid"
        else:
            assert param["type"] == "integer" and param["exclusiveMinimum"] == 0
        assert schema.json()["paths"][archive][method]["responses"]["200"]["content"][
            "application/json"]["schema"]["$ref"] == "#/components/schemas/" + model
