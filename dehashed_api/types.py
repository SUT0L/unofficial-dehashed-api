from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List


class SearchType(Enum):
    email = "email"
    username = "username"
    ip_address = "ip_address"
    domain = "domain"
    name = "name"
    password = "password"
    hashed_password = "hashed_password"
    phone = "phone"
    address = "address"
    company = "company"
    url = "url"
    database_name = "database_name"
    id = "id"


@dataclass
class SearchParams:
    search_type: str
    query: str
    page: int = 1
    regex: bool = False
    wildcard: bool = False
    deduplicate: bool = True


@dataclass
class RequestConfig:
    url: str
    method: str
    headers: Dict[str, str]
    payload: Dict[str, Any]


@dataclass
class DehashedResult:
    id: str
    primary_field: str
    email: List[str] = field(default_factory=list)
    name: List[str] = field(default_factory=list)
    address: List[str] = field(default_factory=list)
    phone: List[str] = field(default_factory=list)
    company: List[str] = field(default_factory=list)
    url: List[str] = field(default_factory=list)
    database_name: str = ""
    password: List[str] = field(default_factory=list)
    hashed_password: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SearchResponse:
    assets_searched: int
    data_wells: int
    total_results: int
    next_page: bool
    elapsed_time: int
    results: List[DehashedResult]
    has_access: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assets_searched": self.assets_searched,
            "data_wells": self.data_wells,
            "total_results": self.total_results,
            "next_page": self.next_page,
            "elapsed_time": self.elapsed_time,
            "results": [r.to_dict() for r in self.results],
            "has_access": self.has_access,
        }


