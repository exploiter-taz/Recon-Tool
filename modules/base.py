"""Abstract base class for all recon modules."""

from abc import ABC, abstractmethod

from core.context import Context


class BaseReconModule(ABC):
    """Base class that every recon module must inherit from.

    Provides the contract for name, description, validation, and execution.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name identifier for this module."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a human-readable description of what this module does."""

    @abstractmethod
    def validate(self, context: Context) -> bool:
        """Validate that the module can run with the given context.

        Args:
            context: Shared state container for the recon pipeline.

        Returns:
            True if the context satisfies all preconditions, False otherwise.
        """

    @abstractmethod
    def run(self, context: Context) -> None:
        """Execute the recon module, enriching *context* with results.

        Args:
            context: Shared state container that the module reads from and
                     writes results into.
        """
