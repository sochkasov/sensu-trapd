from sensu.snmp.event import TrapEvent
from sensu.snmp.log import log


class TrapHandler(object):

    def __init__(self, trap_type, trap_args, event_name, event_output, event_handlers, event_severity, predicates=None):
        if predicates is None:
            predicates = dict()

        self.trap_type = trap_type
        self.trap_args = trap_args
        self.event_name = event_name
        self.event_output = event_output
        self.event_handlers = event_handlers
        self.event_severity = event_severity
        self.predicates = predicates

    def handles(self, trap):
        if trap.oid == self.trap_type:
            log.debug("  -1- trap.arguments=%s \n" % (trap.arguments))
            for trap_arg in trap.arguments:
                log.debug("  -2- trap_arg=%s \n" % (trap_arg))
                # Ignore OIDs
                if (str(trap_arg) not in ['1.3.6.1.2.1.1.3.0','1.3.6.1.2.1.1.3','1.3.6.1.6.3.18.1.4','1.3.6.1.6.3.1.1.4.3','1.3.6.1.6.3.18.1.3']) and trap_arg not in self.trap_args.keys():
                    log.debug("  -3- srt(trap_arg)=%s \n  - trap_arg=%s \n  - self.trap_arg.keys()=%s \n RETURN FALSE" % (str(trap_arg), trap_arg, self.trap_args.keys()))
                    return False
            return True
        return False

    def _build_substitutions(self, trap):
        substitutions = dict()

        # add default substitutions
        substitutions['oid'] = str(trap.oid)

        # build substitution list from trap properties
        for k, v in trap.properties.items():
            substitutions[k] = str(v)

        # build substitution list from trap arguments
        for trap_arg_type_oid, token in self.trap_args.items():
            if trap_arg_type_oid in trap.arguments:
                substitutions[token] = str(trap.arguments[trap_arg_type_oid])

        return substitutions

    def _do_substitutions(self, pattern, substitutions):
        return pattern.format(**substitutions)

    def transform(self, trap):
        substitutions = self._build_substitutions(trap)
        return TrapEvent(self._do_substitutions(self.event_name, substitutions),
                         self._do_substitutions(self.event_output, substitutions),
                         self.event_severity,
                         self.event_handlers)
