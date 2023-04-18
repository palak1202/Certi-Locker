import { Box, Typography } from "@mui/material";

import styles from "../styles/components/Copyright.module.css";

const Copyright = (props) => {
    return (
        <Box className={styles.copyright}>
            <Typography variant="body2" color="black" align="center" {...props}>
                {`© CertiLocker ${new Date().getFullYear()}`}
            </Typography>
        </Box>
    );
};

export default Copyright;
