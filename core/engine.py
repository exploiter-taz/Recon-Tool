"""Pipeline engine that orchestrates recon module execution."""

import logging
from collections.abc import Sequence

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class Engine:
    """Orchestrates a sequence of recon modules against a shared context.

    Each module is validated before execution.  A single module failure
    never halts the pipeline; errors are logged and the engine moves to
    the next module.
    """

    def __init__(self, modules: Sequence[BaseReconModule]) -> None:
        """Inject the list of modules to run.

        Args:
            modules: Ordered collection of recon module instances.
        """
        self._modules = list(modules)

    def run(self, context: Context) -> Context:
        """Execute every module against *context* in insertion order.

        Args:
            context: Shared state that each module reads from and writes to.

        Returns:
            The enriched context after all modules have run.
        """
        for module in self._modules:
            try:
                if not module.validate(context):
                    logger.warning(
                        "Module '%s' skipped — validation failed.",
                        module.name,
                    )
                    continue

                module.run(context)
                logger.info("Module '%s' completed successfully.", module.name)

            except Exception:
                logger.exception(
                    "Module '%s' raised an unexpected error — continuing.",
                    module.name,
                )

        return context
